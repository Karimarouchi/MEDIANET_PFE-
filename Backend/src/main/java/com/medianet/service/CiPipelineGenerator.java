package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Writes the Woodpecker pipeline of a repository from its file list: one step per project found (Maven, Gradle, npm,
 * Python, Composer) running its own tests / lint / build, plus the Vulnix scan gate. Nothing is added to the repository.
 * Pure function of its inputs, so every rule is unit-tested.
 */
final class CiPipelineGenerator {

    /** Step names: the UI recognises the prefix to label them. */
    static final String SCAN_STEP = "vulnix-scan";
    static final int MAX_DEPTH = 4;
    private static final Pattern SKIP = Pattern.compile("(^|/)(node_modules|vendor|target|build|dist|\\.git)/");
    private static final Pattern JAVA_VERSION = Pattern.compile(
            "<(?:java\\.version|maven\\.compiler\\.release|maven\\.compiler\\.source|release)>\\s*(?:1\\.)?(\\d+)\\s*<");
    private static final ObjectMapper JSON = new ObjectMapper();

    /** How the scan step reaches Vulnix. */
    record VulnixTarget(String url, long repositoryId) {
    }

    private CiPipelineGenerator() {
    }

    /** Manifests whose content the generator needs (pom.xml, package.json); read before calling {@link #generate}. */
    static List<String> manifestsToRead(Collection<String> paths) {
        List<String> out = new ArrayList<>();
        for (String p : usable(paths)) {
            String name = name(p);
            if (name.equals("pom.xml") || name.equals("package.json")) out.add(p);
        }
        return out;
    }

    static String generate(Collection<String> paths, Map<String, String> manifests, VulnixTarget vulnix) {
        TreeSet<String> files = usable(paths);
        StringBuilder y = new StringBuilder();
        y.append("# Pipeline écrit par Vulnix pour ce dépôt (rien n'est ajouté au dépôt).\n");
        y.append("when:\n  - event: [push, manual, tag]\n\n");
        y.append("steps:\n");

        List<String> poms = topMost(files, "pom.xml");
        for (String pom : poms) {
            String dir = dir(pom);
            int java = javaVersion(manifests.get(pom));
            boolean wrapper = files.contains(join(dir, "mvnw"));
            step(y, "maven" + suffix(dir), "maven:3.9-eclipse-temurin-" + java, dir,
                    List.of((wrapper ? "sh ./mvnw" : "mvn") + " -B -ntp verify"), Map.of());
        }
        for (String gradle : topMost(files, "build.gradle", "build.gradle.kts")) {
            String dir = dir(gradle);
            if (poms.stream().anyMatch(p -> dir(p).equals(dir))) continue;
            boolean wrapper = files.contains(join(dir, "gradlew"));
            step(y, "gradle" + suffix(dir), "gradle:8-jdk17", dir,
                    List.of(wrapper ? "sh ./gradlew build --no-daemon" : "gradle build --no-daemon"), Map.of());
        }
        for (String pkg : npmRoots(files, manifests)) {
            String dir = dir(pkg);
            JsonNode json = parse(manifests.get(pkg));
            List<String> cmds = new ArrayList<>();
            cmds.add(files.contains(join(dir, "package-lock.json")) ? "npm ci --no-audit --no-fund"
                    : "npm install --no-audit --no-fund");
            boolean workspaces = json != null && json.has("workspaces");
            for (String script : List.of("test", "lint", "build")) {
                if (hasScript(json, script)) {
                    cmds.add("npm run " + script);
                } else if (workspaces) {
                    cmds.add("npm run " + script + " --workspaces --if-present");
                }
            }
            step(y, "npm" + suffix(dir), "node:" + nodeVersion(json), dir, cmds, Map.of("CI", "true"));
        }
        for (String req : topMost(files, "requirements.txt", "pyproject.toml")) {
            String dir = dir(req);
            List<String> cmds = new ArrayList<>();
            cmds.add(name(req).equals("requirements.txt") ? "pip install -q -r requirements.txt" : "pip install -q .");
            if (files.stream().anyMatch(f -> f.startsWith(dir.isEmpty() ? "" : dir + "/") && name(f).matches("test_.*\\.py|.*_test\\.py"))) {
                cmds.add("pip install -q pytest");
                cmds.add("python -m pytest -q");
            }
            step(y, "python" + suffix(dir), "python:3.12-slim", dir, cmds, Map.of());
        }
        for (String composer : topMost(files, "composer.json")) {
            String dir = dir(composer);
            List<String> cmds = new ArrayList<>(List.of("composer install --no-interaction --no-progress"));
            if (files.contains(join(dir, "phpunit.xml")) || files.contains(join(dir, "phpunit.xml.dist"))) {
                cmds.add("vendor/bin/phpunit");
            }
            step(y, "php" + suffix(dir), "composer:2", dir, cmds, Map.of());
        }

        scanStep(y, vulnix);
        return y.toString();
    }

    /** Pipeline that fails at once with a readable reason (shown in Vulnix). */
    static String failing(String reason) {
        StringBuilder y = new StringBuilder("when:\n  - event: [push, manual, tag]\n\nsteps:\n");
        step(y, "vulnix-config", "alpine:3.20", "", List.of("echo " + shellQuote("Vulnix : " + reason), "exit 1"), Map.of());
        return y.toString();
    }

    private static void scanStep(StringBuilder y, VulnixTarget v) {
        y.append("  - name: ").append(SCAN_STEP).append("\n");
        y.append("    image: python:3.12-alpine\n");
        // No extra_hosts: Woodpecker only allows it on trusted repos. Docker Desktop resolves host.docker.internal by
        // itself; on a server, vulnix.ci.woodpecker.callback-url is Vulnix's public address.
        y.append("    depends_on: []\n");
        y.append("    environment:\n");
        y.append("      VULNIX_URL: ").append(q(v.url())).append("\n");
        y.append("      VULNIX_REPO_ID: ").append(q(String.valueOf(v.repositoryId()))).append("\n");
        y.append("      VULNIX_TOKEN:\n        from_secret: vulnix_token\n");
        y.append("    commands:\n      - |\n        cat > /tmp/gate.py <<'PY'\n");
        for (String line : GATE.split("\n")) y.append("        ").append(line).append("\n");
        y.append("        PY\n        python3 -u /tmp/gate.py\n");
    }

    /**
     * Starts the Vulnix scan of this commit, waits for it, then applies the Vulnix verdict (CVSS critical/high or
     * KEV, minus approved exceptions). No dollar sign on purpose: Woodpecker substitutes variables in the YAML.
     */
    static final String GATE = String.join("\n",
            "import json, os, sys, time, urllib.error, urllib.request",
            "api = os.environ['VULNIX_URL'].rstrip('/')",
            "token = os.environ.get('VULNIX_TOKEN', '')",
            "repo = int(os.environ['VULNIX_REPO_ID'])",
            "sha = os.environ['CI_COMMIT_SHA']",
            "if not token:",
            "    print('Jeton Vulnix absent : reactivez la CI de ce depot dans Vulnix.')",
            "    sys.exit(2)",
            "def call(method, path, body=None):",
            "    data = json.dumps(body).encode() if body is not None else None",
            "    req = urllib.request.Request(api + path, data=data, method=method,",
            "        headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})",
            "    try:",
            "        with urllib.request.urlopen(req, timeout=60) as r:",
            "            return json.load(r)",
            "    except urllib.error.HTTPError as e:",
            "        print('Vulnix a refuse la demande (HTTP %s) : %s' % (e.code, e.read().decode()[:300]))",
            "        sys.exit(2)",
            "    except urllib.error.URLError as e:",
            "        print('Vulnix injoignable a %s : %s' % (api, e.reason))",
            "        sys.exit(2)",
            "scan = call('POST', '/api/ci/scans', {'repositoryId': repo, 'commitSha': sha, 'ref': os.environ.get('CI_COMMIT_REF', '')})",
            "sid = scan['scanId']",
            "print('Scan Vulnix #%s du commit %s%s' % (sid, sha[:12], ' (resultat deja disponible)' if scan.get('reused') else ''))",
            "deadline = time.time() + 45 * 60",
            "status = scan.get('status')",
            "while status in ('PENDING', 'RUNNING'):",
            "    if time.time() > deadline:",
            "        print('Le scan depasse 45 minutes : arret de l etape.')",
            "        sys.exit(2)",
            "    time.sleep(15)",
            "    status = call('GET', '/api/ci/scans/%s' % sid).get('status')",
            "    print('  etat du scan : %s' % status)",
            "if status != 'COMPLETED':",
            "    print('Le scan Vulnix a fini en %s.' % status)",
            "    sys.exit(2)",
            "v = call('GET', '/api/ci/verdict?repositoryId=%s&sha=%s' % (repo, sha))",
            "blocking = v.get('blocking') or []",
            "ignored = v.get('ignored') or []",
            "for f in blocking:",
            "    print('  BLOQUANT %-9s %-20s %s%s' % (f.get('severity'), f.get('cveId'), f.get('packageName') or '', ' (KEV)' if f.get('kev') else ''))",
            "if ignored:",
            "    print('  %d vulnerabilite(s) acceptee(s) par une exception validee.' % len(ignored))",
            "print('Rapport : %s' % v.get('reportUrl'))",
            "if v.get('verdict') == 'PASS':",
            "    print('Barriere Vulnix : OK, aucune vulnerabilite bloquante.')",
            "    sys.exit(0)",
            "print('Barriere Vulnix : ECHEC, %d vulnerabilite(s) bloquante(s) (critique, elevee ou KEV).' % len(blocking))",
            "sys.exit(1)");

    private static void step(StringBuilder y, String name, String image, String dir, List<String> commands,
            Map<String, String> env) {
        y.append("  - name: ").append(name).append("\n");
        y.append("    image: ").append(image).append("\n");
        y.append("    depends_on: []\n");
        if (!dir.isEmpty()) y.append("    directory: ").append(q(dir)).append("\n");
        if (!env.isEmpty()) {
            y.append("    environment:\n");
            env.forEach((k, v) -> y.append("      ").append(k).append(": ").append(q(v)).append("\n"));
        }
        y.append("    commands:\n");
        for (String c : commands) y.append("      - ").append(q(c)).append("\n");
    }

    // ── file list helpers ────────────────────────────────────────────────────────

    /** Paths where a project root (pom.xml, package.json…) may sit: not too deep, outside dependency folders. */
    static TreeSet<String> usable(Collection<String> paths) {
        return normalized(paths, MAX_DEPTH + 1);
    }

    /** Every file outside dependency and build folders, whatever its depth (sources and tests). */
    static TreeSet<String> normalized(Collection<String> paths, int maxSegments) {
        TreeSet<String> out = new TreeSet<>();
        for (String raw : paths == null ? List.<String>of() : paths) {
            if (raw == null || raw.isBlank()) continue;
            String p = raw.replace('\\', '/').replaceAll("^/+", "");
            if (SKIP.matcher(p).find() || p.contains("..")) continue;
            if (p.split("/").length > maxSegments) continue;
            out.add(p);
        }
        return out;
    }

    /** Files with one of these names, without those nested under another of the same kind (Maven modules). */
    static List<String> topMost(TreeSet<String> files, String... names) {
        List<String> found = files.stream().filter(f -> List.of(names).contains(name(f))).toList();
        List<String> out = new ArrayList<>();
        for (String f : found) {
            String d = dir(f);
            boolean nested = found.stream().anyMatch(o -> !o.equals(f) && isUnder(d, dir(o)));
            if (!nested) out.add(f);
        }
        return out;
    }

    /** package.json files that are not a workspace member of a parent package.json. */
    static List<String> npmRoots(TreeSet<String> files, Map<String, String> manifests) {
        List<String> all = files.stream().filter(f -> name(f).equals("package.json")).toList();
        List<String> out = new ArrayList<>();
        for (String f : all) {
            String d = dir(f);
            boolean member = all.stream().anyMatch(o -> !o.equals(f) && isUnder(d, dir(o))
                    && parse(manifests.get(o)) != null && parse(manifests.get(o)).has("workspaces"));
            if (!member) out.add(f);
        }
        return out;
    }

    static boolean isUnder(String dir, String parent) {
        if (dir.equals(parent)) return false;
        return parent.isEmpty() || dir.startsWith(parent + "/");
    }

    static int javaVersion(String pom) {
        if (pom != null) {
            Matcher m = JAVA_VERSION.matcher(pom);
            if (m.find()) {
                int v = Integer.parseInt(m.group(1));
                for (int supported : new int[] {8, 11, 17, 21, 25}) {
                    if (v <= supported) return supported;
                }
            }
        }
        return 17;
    }

    static String nodeVersion(JsonNode pkg) {
        String engines = pkg == null ? "" : pkg.path("engines").path("node").asText("");
        Matcher m = Pattern.compile("(\\d{2})").matcher(engines);
        if (m.find()) {
            int v = Integer.parseInt(m.group(1));
            if (v >= 16 && v <= 24) return String.valueOf(v % 2 == 1 ? v + 1 : v);
        }
        return "20";
    }

    static boolean hasScript(JsonNode pkg, String script) {
        return pkg != null && pkg.path("scripts").hasNonNull(script);
    }

    static JsonNode parse(String json) {
        if (json == null) return null;
        try {
            return JSON.readTree(json);
        } catch (Exception e) {
            return null;
        }
    }

    static String suffix(String dir) {
        if (dir.isEmpty()) return "";
        String slug = dir.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-").replaceAll("(^-|-$)", "");
        return slug.isEmpty() ? "" : "-" + slug;
    }

    static String name(String p) {
        int i = p.lastIndexOf('/');
        return i < 0 ? p : p.substring(i + 1);
    }

    static String dir(String p) {
        int i = p.lastIndexOf('/');
        return i < 0 ? "" : p.substring(0, i);
    }

    static String join(String dir, String file) {
        return dir.isEmpty() ? file : dir + "/" + file;
    }

    /** YAML single-quoted scalar; a dollar would be expanded by Woodpecker, so it is escaped as $$. */
    static String q(String s) {
        return "'" + s.replace("'", "''").replace("$", "$$") + "'";
    }

    private static String shellQuote(String s) {
        return "\"" + s.replace("\\", "").replace("\"", "'").replace("`", "'") + "\"";
    }
}
