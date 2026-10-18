package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * What the CI will run on a repository, which tests are missing and which problems will turn it red anyway, from
 * its file list (same rules as {@link CiPipelineGenerator}). Also writes the prompt the user gives to an AI assistant:
 * it asks for test code and test configuration only, nothing run on the developer's machine (the CI runs it).
 * The prompt carries paths and build setup only: no source code and no secret leaves Vulnix.
 */
public final class CiRepoAnalyzer {

    private static final int MAX_TARGETS = 20;
    private static final Pattern BOOT_VERSION = Pattern.compile(
            "<artifactId>spring-boot-starter-parent</artifactId>\\s*<version>([^<]+)</version>");
    private static final Pattern JAVA_CLASS_TARGET = Pattern.compile(
            ".*/src/main/java/.+(Service|ServiceImpl|Controller|Mapper|Util|Utils|Validator|Calculator)\\.java$");
    private static final Pattern FRONT_SOURCE = Pattern.compile(
            ".*/src/(components|pages|features|utils|services|hooks|lib|store|context)/.+\\.(jsx?|tsx?)$");
    private static final Pattern FRONT_TEST = Pattern.compile(".*(\\.(test|spec)\\.(jsx?|tsx?)|/__tests__/.+)$");
    private static final List<String> ESLINT_CONFIGS = List.of("eslint.config.js", "eslint.config.mjs", "eslint.config.cjs",
            "eslint.config.ts", ".eslintrc", ".eslintrc.js", ".eslintrc.cjs", ".eslintrc.json", ".eslintrc.yml");

    /**
     * One part of the repository = one CI step. {@code rules}: how to write its tests; {@code warnings}: problems
     * that make its step fail whatever the tests (shown in Vulnix and put in the prompt).
     */
    public record Part(String kind, String dir, String step, String stack, boolean hasTests, int testFiles,
            String missing, List<String> commands, List<String> targets, List<String> rules, List<String> warnings) {
    }

    public record Analysis(List<Part> parts, List<String> plannedSteps, String prompt) {
    }

    /** Facts about one front-end application that change the instructions. */
    record FrontApp(String dir, boolean typescript, String viteConfig, int viteMajor, int reactMajor, boolean cra,
            String existingRunner, boolean eslintMissing, boolean buildRunsTsc) {
    }

    private CiRepoAnalyzer() {
    }

    static Analysis analyze(String fullName, String branch, Collection<String> paths, Map<String, String> manifests) {
        return analyze(fullName, branch, paths, manifests, null, null);
    }

    /**
     * @param steps steps the prompt covers (null = all parts)
     * @param focus theme to limit the prompt to, matched against file paths ("auth"); null = everything
     */
    static Analysis analyze(String fullName, String branch, Collection<String> paths, Map<String, String> manifests,
            Set<String> steps, String focus) {
        TreeSet<String> files = CiPipelineGenerator.usable(paths);
        TreeSet<String> all = CiPipelineGenerator.normalized(paths, Integer.MAX_VALUE);
        List<Part> parts = new ArrayList<>();

        for (String pom : CiPipelineGenerator.topMost(files, "pom.xml")) {
            String dir = CiPipelineGenerator.dir(pom);
            String prefix = dir.isEmpty() ? "" : dir + "/";
            String content = manifests.getOrDefault(pom, "");
            int java = CiPipelineGenerator.javaVersion(content);
            List<String> tests = all.stream().filter(f -> f.startsWith(prefix + "src/test/") && f.endsWith(".java")).toList();
            // Business logic first (services, then helpers), controllers after: unit tests pay off most there.
            // Classes that already have a <Name>Test.java are left out: the prompt targets what is not tested yet.
            Set<String> tested = tests.stream().map(t -> CiPipelineGenerator.name(t).replaceAll("(Tests?|IT)\\.java$", ".java"))
                    .collect(Collectors.toSet());
            List<String> targets = all.stream().filter(f -> f.startsWith(prefix) && JAVA_CLASS_TARGET.matcher("/" + f).matches())
                    .filter(f -> !tested.contains(CiPipelineGenerator.name(f)))
                    .sorted(Comparator.comparingInt(CiRepoAnalyzer::javaPriority).thenComparing(f -> f)).toList();
            parts.add(new Part("maven", dir, "maven" + CiPipelineGenerator.suffix(dir), mavenStack(content, java),
                    !tests.isEmpty(), tests.size(),
                    tests.isEmpty() ? "aucun test (rien sous " + prefix + "src/test/java)" : null,
                    List.of((files.contains(CiPipelineGenerator.join(dir, "mvnw")) ? "sh ./mvnw" : "mvn") + " -B -ntp verify"),
                    targets, javaRules(prefix, content), List.of()));
        }

        for (String pkg : CiPipelineGenerator.npmRoots(files, manifests)) {
            String dir = CiPipelineGenerator.dir(pkg);
            JsonNode root = CiPipelineGenerator.parse(manifests.get(pkg));
            List<String> members = workspaceMembers(files, dir, root);
            boolean workspaces = root != null && root.has("workspaces");
            boolean lock = files.contains(CiPipelineGenerator.join(dir, "package-lock.json"));
            List<String> commands = new ArrayList<>();
            commands.add(lock ? "npm ci" : "npm install");
            for (String script : List.of("test", "lint", "build")) {
                if (CiPipelineGenerator.hasScript(root, script)) commands.add("npm run " + script);
                else if (workspaces) commands.add("npm run " + script + " --workspaces --if-present");
            }
            List<String> missing = new ArrayList<>();
            List<String> targets = new ArrayList<>();
            List<String> stacks = new ArrayList<>();
            List<String> warnings = new ArrayList<>();
            List<FrontApp> apps = new ArrayList<>();
            int testCount = 0;
            boolean allTested = true;
            for (String m : members) {
                String mPrefix = m.isEmpty() ? "" : m + "/";
                JsonNode mPkg = CiPipelineGenerator.parse(manifests.get(CiPipelineGenerator.join(m, "package.json")));
                long tests = all.stream().filter(f -> f.startsWith(mPrefix) && FRONT_TEST.matcher("/" + f).matches()).count();
                boolean script = CiPipelineGenerator.hasScript(mPkg, "test") || (m.equals(dir) && CiPipelineGenerator.hasScript(root, "test"));
                testCount += (int) tests;
                String where = m.isEmpty() ? "racine" : m;
                stacks.add(where + " : " + frontStack(mPkg));
                if (!script || tests == 0) {
                    allTested = false;
                    missing.add(where + (script ? " (script test présent, aucun fichier de test)" : " (pas de script \"test\" ni de fichier de test)"));
                }
                String lint = mPkg == null ? "" : mPkg.path("scripts").path("lint").asText("");
                boolean eslintMissing = lint.contains("eslint") && !hasDep(mPkg, "eslint") && !hasDep(root, "eslint");
                if (eslintMissing) {
                    boolean config = ESLINT_CONFIGS.stream().anyMatch(c -> all.contains(mPrefix + c));
                    warnings.add("`npm run lint` échouera dans " + where + " : le script appelle eslint, mais eslint n'est pas dans les devDependencies"
                            + (config ? " (une config ESLint existe)." : " et aucune config ESLint n'existe."));
                }
                apps.add(frontApp(all, m, mPkg, eslintMissing));
                all.stream().filter(f -> f.startsWith(mPrefix) && FRONT_SOURCE.matcher("/" + f).matches() && !FRONT_TEST.matcher("/" + f).matches())
                        .forEach(targets::add);
            }
            parts.add(new Part("npm", dir, "npm" + CiPipelineGenerator.suffix(dir), String.join(" · ", stacks),
                    allTested, testCount, missing.isEmpty() ? null : String.join(" ; ", missing), commands, targets,
                    npmRules(dir, apps, workspaces, lock, commands.stream().anyMatch(c -> c.contains("run lint"))), warnings));
        }

        for (String req : CiPipelineGenerator.topMost(files, "requirements.txt", "pyproject.toml")) {
            String dir = CiPipelineGenerator.dir(req);
            String prefix = dir.isEmpty() ? "" : dir + "/";
            long tests = all.stream().filter(f -> f.startsWith(prefix) && CiPipelineGenerator.name(f).matches("test_.*\\.py|.*_test\\.py")).count();
            parts.add(new Part("python", dir, "python" + CiPipelineGenerator.suffix(dir), "Python", tests > 0, (int) tests,
                    tests == 0 ? "aucun fichier test_*.py" : null, List.of("python -m pytest -q"), List.of(),
                    List.of("pytest, fichiers `test_*.py` dans `" + (dir.isEmpty() ? "tests" : dir + "/tests")
                            + "`. Ajoute `pytest` aux dépendances de développement."), List.of()));
        }

        for (String composer : CiPipelineGenerator.topMost(files, "composer.json")) {
            String dir = CiPipelineGenerator.dir(composer);
            boolean phpunit = files.contains(CiPipelineGenerator.join(dir, "phpunit.xml")) || files.contains(CiPipelineGenerator.join(dir, "phpunit.xml.dist"));
            parts.add(new Part("php", dir, "php" + CiPipelineGenerator.suffix(dir), "PHP (Composer)", phpunit, 0,
                    phpunit ? null : "pas de phpunit.xml", List.of("vendor/bin/phpunit"), List.of(),
                    List.of("PHPUnit : `phpunit.xml` à la racine de la partie, tests dans `tests/`, `phpunit/phpunit` en require-dev."), List.of()));
        }

        List<String> planned = new ArrayList<>(List.of("clone"));
        parts.forEach(p -> planned.add(p.step()));
        planned.add(CiPipelineGenerator.SCAN_STEP);
        return new Analysis(parts, planned, prompt(fullName, branch, parts, steps, focus));
    }

    /** "backoffice", "frontoffice" for a root with workspaces; the root itself otherwise. */
    static List<String> workspaceMembers(TreeSet<String> files, String dir, JsonNode root) {
        if (root == null) return List.of(dir);
        JsonNode ws = root.path("workspaces").isArray() ? root.path("workspaces") : root.path("workspaces").path("packages");
        if (!ws.isArray() || ws.isEmpty()) return List.of(dir);
        List<String> out = new ArrayList<>();
        for (JsonNode w : ws) {
            String pattern = CiPipelineGenerator.join(dir, w.asText().replaceAll("/+$", ""));
            if (pattern.endsWith("/*")) {
                String parent = pattern.substring(0, pattern.length() - 2);
                files.stream().filter(f -> CiPipelineGenerator.name(f).equals("package.json"))
                        .map(CiPipelineGenerator::dir).filter(d -> CiPipelineGenerator.dir(d).equals(parent)).forEach(out::add);
            } else if (files.contains(CiPipelineGenerator.join(pattern, "package.json"))) {
                out.add(pattern);
            }
        }
        return out.isEmpty() ? List.of(dir) : out;
    }

    static int javaPriority(String path) {
        if (path.matches(".*(Service|ServiceImpl)\\.java$")) return 0;
        if (path.matches(".*(Util|Utils|Validator|Calculator|Mapper)\\.java$")) return 1;
        return 2;
    }

    static String mavenStack(String pom, int java) {
        StringBuilder s = new StringBuilder();
        Matcher boot = BOOT_VERSION.matcher(pom == null ? "" : pom);
        s.append(boot.find() ? "Spring Boot " + boot.group(1).trim() : "Maven").append(" · Java ").append(java);
        List<String> extras = new ArrayList<>();
        if (pom != null) {
            if (pom.contains("spring-boot-starter-web")) extras.add("Web");
            if (pom.contains("spring-boot-starter-data-jpa")) extras.add("JPA");
            if (pom.contains("spring-boot-starter-security")) extras.add("Security");
            if (pom.contains("postgresql")) extras.add("PostgreSQL");
            if (pom.contains("mysql")) extras.add("MySQL");
            if (pom.contains("<artifactId>h2</artifactId>")) extras.add("H2");
        }
        if (!extras.isEmpty()) s.append(" (").append(String.join(", ", extras)).append(")");
        return s.toString();
    }

    static String frontStack(JsonNode pkg) {
        if (pkg == null) return "npm";
        List<String> out = new ArrayList<>();
        for (String[] lib : new String[][] {{"react", "React"}, {"vue", "Vue"}, {"@angular/core", "Angular"}, {"next", "Next.js"},
                {"vite", "Vite"}, {"react-scripts", "Create React App"}, {"typescript", "TypeScript"}, {"vitest", "Vitest"}, {"jest", "Jest"}}) {
            int v = major(pkg, lib[0]);
            if (hasDep(pkg, lib[0])) out.add(lib[1] + (v > 0 ? " " + v : ""));
        }
        return out.isEmpty() ? "npm" : String.join(", ", out);
    }

    static FrontApp frontApp(TreeSet<String> all, String dir, JsonNode pkg) {
        return frontApp(all, dir, pkg, false);
    }

    static FrontApp frontApp(TreeSet<String> all, String dir, JsonNode pkg, boolean eslintMissing) {
        String prefix = dir.isEmpty() ? "" : dir + "/";
        boolean ts = all.contains(prefix + "tsconfig.json") || all.stream().anyMatch(f -> f.startsWith(prefix + "src/") && f.endsWith(".tsx"));
        String viteConfig = List.of("vite.config.ts", "vite.config.mts", "vite.config.js", "vite.config.mjs").stream()
                .filter(n -> all.contains(prefix + n)).findFirst().orElse(null);
        String runner = hasDep(pkg, "vitest") ? "vitest" : hasDep(pkg, "jest") ? "jest" : null;
        boolean tsc = pkg != null && pkg.path("scripts").path("build").asText("").matches(".*\\btsc\\b.*");
        return new FrontApp(dir, ts, viteConfig, major(pkg, "vite"), major(pkg, "react"), hasDep(pkg, "react-scripts"), runner,
                eslintMissing, tsc);
    }

    private static boolean hasDep(JsonNode pkg, String name) {
        return pkg != null && (pkg.path("dependencies").has(name) || pkg.path("devDependencies").has(name));
    }

    private static int major(JsonNode pkg, String name) {
        if (pkg == null) return 0;
        String v = pkg.path("dependencies").path(name).asText(pkg.path("devDependencies").path(name).asText(""));
        Matcher m = Pattern.compile("(\\d+)").matcher(v);
        return m.find() ? Integer.parseInt(m.group(1)) : 0;
    }

    // ── instructions per part ───────────────────────────────────────────────────

    static List<String> javaRules(String prefix, String pom) {
        List<String> r = new ArrayList<>();
        boolean starterTest = pom != null && pom.contains("spring-boot-starter-test");
        boolean security = pom != null && pom.contains("spring-boot-starter-security");
        r.add(starterTest
                ? "JUnit 5 + Mockito + AssertJ : déjà fournis par `spring-boot-starter-test` dans `" + prefix + "pom.xml`."
                : "Ajoute à la main dans `" + prefix + "pom.xml` la dépendance `org.springframework.boot:spring-boot-starter-test` en `<scope>test</scope>`, sans version (gérée par Spring Boot).");
        if (security) {
            r.add(pom.contains("spring-security-test")
                    ? "`spring-security-test` est présent : `@WithMockUser` ou un utilisateur de test pour les routes protégées."
                    : "Spring Security est présent : ajoute à la main `org.springframework.security:spring-security-test` en `<scope>test</scope>`, sans version.");
        }
        r.add("Emplacement : `" + prefix + "src/test/java/<package de la classe>/<Classe>Test.java`.");
        r.add("Tests unitaires des services et utilitaires : `@ExtendWith(MockitoExtension.class)`, dépendances en `@Mock`, classe testée en `@InjectMocks` ; cas normal, cas limites et erreurs attendues.");
        r.add("Tests fonctionnels des contrôleurs : `@WebMvcTest(<Contrôleur>.class)` + `@MockBean` des services ; envoie de vraies requêtes HTTP avec MockMvc (corps JSON) et vérifie le code de réponse, les champs JSON renvoyés, les erreurs de validation (400)"
                + (security ? ", l'accès refusé sans authentification (401/403) et autorisé avec. Importe la vraie configuration de sécurité (`@Import`) pour tester les vraies règles d'accès." : "."));
        r.add("Pas de `@SpringBootTest` qui démarre toute l'application : elle chercherait sa base de données, absente de la CI. "
                + "Si un test d'intégration est indispensable, ajoute `com.h2database:h2` en scope test et `" + prefix
                + "src/test/resources/application.properties` pointant sur H2.");
        return r;
    }

    /** ESLint flat config for a Vite + React app, written so the existing code passes (rules it may break are warnings). */
    static String eslintConfig(boolean typescript) {
        String files = typescript ? "**/*.{ts,tsx}" : "**/*.{js,jsx}";
        StringBuilder c = new StringBuilder();
        c.append("import js from '@eslint/js'\n")
                .append("import globals from 'globals'\n")
                .append("import reactHooks from 'eslint-plugin-react-hooks'\n")
                .append("import reactRefresh from 'eslint-plugin-react-refresh'\n");
        if (typescript) c.append("import tseslint from 'typescript-eslint'\n");
        c.append("\n").append(typescript ? "export default tseslint.config(\n" : "export default [\n")
                .append("  { ignores: ['dist', 'build', 'coverage'] },\n")
                .append("  {\n");
        if (typescript) c.append("    extends: [js.configs.recommended, ...tseslint.configs.recommended],\n");
        else c.append("    ...js.configs.recommended,\n");
        c.append("    files: ['").append(files).append("'],\n")
                .append("    languageOptions: { ecmaVersion: 2022, globals: globals.browser")
                .append(typescript ? "" : ", parserOptions: { ecmaFeatures: { jsx: true } }").append(" },\n")
                .append("    plugins: { 'react-hooks': reactHooks, 'react-refresh': reactRefresh },\n")
                .append("    rules: {\n")
                .append("      ...reactHooks.configs.recommended.rules,\n")
                .append("      // Code existant jamais linté : ces règles avertissent sans bloquer la CI.\n")
                .append("      'react-refresh/only-export-components': 'warn',\n")
                .append("      'react-hooks/exhaustive-deps': 'warn',\n")
                .append("      'no-empty': 'warn',\n")
                .append("      'prefer-const': 'warn',\n");
        if (typescript) {
            c.append("      '@typescript-eslint/no-explicit-any': 'warn',\n")
                    .append("      '@typescript-eslint/no-unused-vars': 'warn',\n")
                    .append("      '@typescript-eslint/no-empty-object-type': 'warn',\n")
                    .append("      '@typescript-eslint/ban-ts-comment': 'warn',\n");
        } else {
            c.append("      'no-unused-vars': 'warn',\n");
        }
        c.append("    },\n").append("  },\n").append(typescript ? ")\n" : "]\n");
        return c.toString();
    }

    static List<String> npmRules(String root, List<FrontApp> apps, boolean workspaces, boolean lock, boolean lint) {
        List<String> r = new ArrayList<>();
        for (FrontApp a : apps) {
            String where = a.dir().isEmpty() ? "la racine" : "`" + a.dir() + "`";
            String prefix = a.dir().isEmpty() ? "" : a.dir() + "/";
            String ext = a.typescript() ? "tsx" : "jsx";
            String setup = "src/setupTests." + (a.typescript() ? "ts" : "js");
            if (a.cra()) {
                r.add("Application " + where + " (Create React App) : Jest est fourni par react-scripts ; ajoute à la main en devDependencies `@testing-library/react`, `@testing-library/user-event` et `@testing-library/jest-dom`, et le script `\"test\": \"react-scripts test --watchAll=false\"`.");
            } else if ("jest".equals(a.existingRunner())) {
                r.add("Application " + where + " : garde Jest, déjà présent ; ajoute le script `\"test\": \"jest\"` s'il manque, et à la main `@testing-library/react`, `@testing-library/user-event` et `jsdom` si besoin.");
            } else {
                String vitest = a.viteMajor() >= 7 ? "^3.2.0" : "^3.0.0";
                String rtl = a.reactMajor() >= 18 ? "^16.0.0" : "^14.0.0";
                r.add("Application " + where + (a.viteMajor() > 0 ? " (Vite " + a.viteMajor() + ", React " + a.reactMajor() + ")" : "")
                        + " : ajoute à la main en devDependencies de son `package.json` : `vitest` " + vitest + ", `@testing-library/react` " + rtl
                        + (a.reactMajor() >= 18 ? ", `@testing-library/dom` ^10.0.0" : "")
                        + ", `@testing-library/user-event` ^14.5.0, `@testing-library/jest-dom` ^6.6.0, `jsdom` ^25.0.0 ; et le script `\"test\": \"vitest run\"`.");
                r.add("Dans " + (a.viteConfig() != null ? "`" + prefix + a.viteConfig() + "`" : "la config Vite de " + where)
                        + " : ajoute `test: { environment: 'jsdom', setupFiles: './" + setup + "' }`"
                        + (a.typescript() ? " et `/// <reference types=\"vitest\" />` en première ligne" : "")
                        + ". Crée `" + prefix + setup + "` contenant seulement `import '@testing-library/jest-dom/vitest'`.");
                r.add("Dans chaque fichier de test, importe explicitement ce que tu utilises (`import { describe, it, expect, vi } from 'vitest'`) : pas de globals, le lint et TypeScript n'ont alors rien à configurer.");
            }
            r.add("Tests de " + where + " à côté du fichier testé : `<Nom>.test." + ext + "`. Unitaires : fonctions, hooks et composants isolés. "
                    + "Fonctionnels : parcours d'écran avec `@testing-library/user-event` (remplir un formulaire, cliquer, vérifier ce qui s'affiche, la redirection, le message d'erreur), "
                    + "routes dans un `MemoryRouter`, réponses de l'API simulées avec `vi.mock` (succès ET erreur), jamais de vrai réseau.");
            if (a.buildRunsTsc()) {
                r.add("Le build de " + where + " lance `tsc` : les fichiers de test sont vérifiés par TypeScript pendant `npm run build`. Ils doivent être correctement typés (pas d'erreur de type, imports explicites), sinon le build échoue.");
            }
            if (a.eslintMissing()) {
                r.add("Réparation demandée (configuration seulement, jamais le code de l'application) : dans " + where
                        + ", `npm run lint` appelle ESLint qui n'est pas installé. Ajoute à la main en devDependencies : `eslint` ^9.17.0, `@eslint/js` ^9.17.0, `globals` ^15.14.0, "
                        + "`eslint-plugin-react-hooks` ^5.1.0, `eslint-plugin-react-refresh` ^0.4.16"
                        + (a.typescript() ? ", `typescript-eslint` ^8.18.0" : "")
                        + ". Crée `" + prefix + "eslint.config.js` avec exactement ce contenu :\n```js\n" + eslintConfig(a.typescript()) + "```\n"
                        + "Ne modifie pas le script `lint`. Les règles marquées `warn` avertissent sans bloquer : ne les passe pas en `error`.");
            }
        }
        r.add(workspaces
                ? "Espace de travail npm : la CI lance `npm run test --workspaces --if-present` depuis `" + (root.isEmpty() ? "la racine" : root) + "`, donc chaque application a son propre script `test`."
                : "Dès que le script `test` existe, la CI lance aussi `npm run test` (elle ne lance que les scripts présents).");
        if (lint) {
            r.add("La CI lance `npm run lint` : les fichiers de test doivent le passer.");
        }
        if (lock) {
            r.add("Un `package-lock.json` existe et la CI fait `npm ci`, qui échoue si le lock ne correspond plus au package.json. Après avoir modifié les package.json, "
                    + "lance UNE seule commande dans `" + (root.isEmpty() ? "la racine" : root) + "` : `npm install --package-lock-only --ignore-scripts` "
                    + "(elle met à jour le lock sans rien installer ni exécuter), et livre le lock mis à jour.");
        }
        return r;
    }

    // ── prompt ──────────────────────────────────────────────────────────────────

    static String prompt(String fullName, String branch, List<Part> allParts, Set<String> steps, String focus) {
        List<Part> parts = steps == null || steps.isEmpty() ? allParts
                : allParts.stream().filter(x -> steps.contains(x.step())).toList();
        String theme = focus == null ? "" : focus.trim().toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9_/-]", "");
        boolean lockStep = parts.stream().anyMatch(x -> x.rules().stream().anyMatch(r -> r.contains("--package-lock-only")));

        StringBuilder p = new StringBuilder();
        p.append("Tu es un développeur senior. Prépare le code des tests automatisés (unitaires et fonctionnels) du dépôt GitHub ").append(fullName)
                .append(" (branche ").append(branch).append(").\n")
                .append("Ton travail : écrire les fichiers de test et la configuration de test. Ce n'est PAS à toi de les exécuter : ")
                .append("la CI (pipeline Woodpecker piloté par Vulnix) les lancera au prochain push et dira ce qui passe ou non.\n");
        if (!theme.isEmpty()) {
            p.append("Périmètre : uniquement ce qui concerne « ").append(theme).append(" » (fichiers dont le chemin contient ce mot, et ce dont ils dépendent directement). Ne teste rien d'autre.\n");
        }
        if (parts.size() < allParts.size()) {
            p.append("Parties concernées : ").append(String.join(", ", parts.stream().map(CiRepoAnalyzer::where).toList()))
                    .append(". Ne touche pas aux autres.\n");
        }
        p.append("\n## Règle d'or : rien ne s'exécute sur cette machine\n")
                .append("- N'installe aucune dépendance (pas de `npm install`, `mvn`, `pip install`), ne lance ni tests, ni build, ni lint, ni serveur.\n")
                .append("- Ajoute les dépendances de test à la main dans les fichiers de build, avec les versions indiquées ci-dessous.\n");
        if (lockStep) p.append("- Seule exception : la mise à jour du lock npm décrite plus bas (elle n'installe et n'exécute rien).\n");
        p.append("- Lis le code de chaque fichier ciblé avant d'écrire ses tests, pour tester son vrai comportement.\n\n");

        p.append("## Ce que la CI exécutera à chaque push\n").append("Une étape par partie du dépôt, chacune dans un conteneur neuf :\n");
        for (Part part : parts) {
            p.append("- ").append(where(part)).append(" : `").append(String.join(" && ", part.commands())).append("`\n");
        }
        p.append("Dans ces conteneurs il n'y a ni base de données, ni autre service, ni variable d'environnement secrète : ")
                .append("les tests doivent tout simuler. Une étape échoue dès qu'une commande échoue.\n\n");

        List<Part> todo = parts.stream().filter(x -> !x.hasTests()).toList();
        p.append("## Ce qui manque aujourd'hui\n");
        if (todo.isEmpty()) p.append("- Chaque partie a déjà des tests : complète-les sur les fichiers listés.\n");
        for (Part part : todo) p.append("- ").append(where(part)).append(" : ").append(part.missing()).append(".\n");
        List<String> warnings = parts.stream().flatMap(x -> x.warnings().stream()).toList();
        if (!warnings.isEmpty()) {
            p.append("\n## Problèmes déjà présents, sans rapport avec les tests\n");
            warnings.forEach(w -> p.append("- ").append(w).append("\n"));
            p.append("Répare-les uniquement comme indiqué plus bas (fichiers de configuration, jamais le code de l'application). Ce qui n'a pas de réparation indiquée : signale-le seulement.\n");
        }

        p.append("\n## Ce que tu dois écrire\n");
        for (Part part : parts) {
            p.append("### ").append(where(part)).append(" — ").append(part.stack()).append("\n");
            part.rules().forEach(r -> p.append("- ").append(r).append("\n"));
            List<String> targets = part.targets().stream()
                    .filter(t -> theme.isEmpty() || t.toLowerCase(Locale.ROOT).contains(theme)).limit(MAX_TARGETS).toList();
            if (!targets.isEmpty()) {
                p.append("- Fichiers à couvrir en priorité :\n");
                targets.forEach(t -> p.append("  - `").append(t).append("`\n"));
            } else if (!theme.isEmpty()) {
                p.append("- Aucun fichier de cette partie ne contient « ").append(theme).append(" » dans son chemin : cherche le code concerné en lisant le dépôt.\n");
            }
            p.append("\n");
        }

        p.append("## Règles de qualité\n")
                .append("- Chaque test vérifie un comportement réel : valeur retournée, exception attendue, appel à une dépendance, texte affiché.\n")
                .append("- Interdit : `assertTrue(true)`, tests vides, tests désactivés (`@Disabled`, `it.skip`, `xit`) ou toute astuce pour faire passer la CI.\n")
                .append("- Ne change pas le code de production. Si en lisant le code tu vois un bug ou une faille, écris le test qui le montre et signale-le à part.\n")
                .append("- Aucun secret, mot de passe réel ni URL de production dans les tests : des valeurs factices.\n\n");

        p.append("## Format de ta réponse\n")
                .append("1. La liste des fichiers créés ou modifiés, avec leur chemin depuis la racine du dépôt.\n")
                .append("2. Le contenu complet de chaque fichier (pas d'extrait), y compris les fichiers de build modifiés.\n")
                .append("3. Pour chaque partie, ce que la CI va exécuter et le résultat attendu.\n")
                .append("4. Les bugs ou failles repérés en lisant le code, s'il y en a.\n")
                .append("5. Le message de commit : `test: tests unitaires pour la CI`.\n");
        return p.toString();
    }

    static String where(Part part) {
        String kind = switch (part.kind()) {
            case "maven" -> "Maven";
            case "npm" -> "npm";
            case "python" -> "Python";
            default -> "PHP";
        };
        return kind + (part.dir().isEmpty() ? " (racine)" : " (`" + part.dir() + "`)");
    }
}
