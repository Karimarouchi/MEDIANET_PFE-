package com.medianet.service;

import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class CiRepoAnalyzerTest {

    private static String res(String name) throws Exception {
        try (InputStream in = CiRepoAnalyzerTest.class.getResourceAsStream("/woodpecker/coussin/" + name)) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static CiRepoAnalyzer.Analysis coussin(List<String> extraFiles) throws Exception {
        List<String> files = new java.util.ArrayList<>(res("files.txt").lines().toList());
        files.addAll(extraFiles);
        Map<String, String> manifests = new HashMap<>();
        for (String m : CiPipelineGenerator.manifestsToRead(files)) {
            try {
                manifests.put(m, res(m));
            } catch (Exception ignored) {
                // extra files of a test have no fixture
            }
        }
        return CiRepoAnalyzer.analyze("Karimarouchi/E-commerce-coussin", "main", files, manifests);
    }

    /** Real tree of E-commerce-coussin: no test anywhere, which is what the CI showed (green but untested). */
    @Test
    void coussinHasNoTestsAndThePromptSaysWhatToWrite() throws Exception {
        CiRepoAnalyzer.Analysis a = coussin(List.of());

        assertThat(a.plannedSteps()).containsExactly("clone", "maven-backend", "npm-frontend", "vulnix-scan");
        CiRepoAnalyzer.Part back = a.parts().get(0);
        assertThat(back.kind()).isEqualTo("maven");
        assertThat(back.hasTests()).isFalse();
        assertThat(back.stack()).startsWith("Spring Boot 3.2.3 · Java 17").contains("JPA").contains("Security");
        assertThat(back.targets()).isNotEmpty().allMatch(t -> t.startsWith("Backend/src/main/java/"));
        assertThat(back.targets().get(0)).endsWith("Service.java"); // services before controllers

        CiRepoAnalyzer.Part front = a.parts().get(1);
        assertThat(front.hasTests()).isFalse();
        assertThat(front.missing()).contains("Frontend/backoffice").contains("Frontend/frontoffice");
        assertThat(front.stack()).contains("React 18").contains("Vite 5");

        String prompt = a.prompt();
        assertThat(prompt)
                .contains("mvn -B -ntp verify")
                .contains("npm run test --workspaces --if-present")
                .contains("Backend/src/test/java/")
                .contains("\"test\": \"vitest run\"")
                .contains("Pas de `@SpringBootTest`")
                .contains("assertTrue(true)");
    }

    @Test
    void existingTestsAreCounted() throws Exception {
        CiRepoAnalyzer.Analysis a = coussin(List.of("Backend/src/test/java/com/x/ProductServiceTest.java"));
        assertThat(a.parts().get(0).hasTests()).isTrue();
        assertThat(a.parts().get(0).testFiles()).isEqualTo(1);
        assertThat(a.prompt()).doesNotContain("Maven (`Backend`) : aucun test");
    }

    @Test
    void npmPartIsTestedOnlyWithScriptAndFiles() {
        CiRepoAnalyzer.Analysis a = CiRepoAnalyzer.analyze("o/r", "main",
                List.of("web/package.json", "web/src/utils/price.js", "web/src/utils/price.test.js"),
                Map.of("web/package.json", "{\"scripts\":{\"test\":\"vitest run\"},\"devDependencies\":{\"vitest\":\"^2.0.0\"}}"));
        CiRepoAnalyzer.Part web = a.parts().get(0);
        assertThat(web.hasTests()).isTrue();
        assertThat(web.testFiles()).isEqualTo(1);
        assertThat(web.targets()).containsExactly("web/src/utils/price.js");
    }

    @Test
    void promptAsksForCodeOnlyNothingRunLocally() throws Exception {
        String prompt = coussin(List.of()).prompt();
        assertThat(prompt).contains("Ce n'est PAS à toi de les exécuter").contains("N'installe aucune dépendance")
                .doesNotContain("Vérifie en local");
    }

    /** Antigone_finance case: one TypeScript app with a lockfile and a lint script whose eslint is not installed. */
    @Test
    void lockfileTypescriptAndBrokenLintAreHandled() {
        List<String> files = List.of("frontend/package.json", "frontend/package-lock.json", "frontend/tsconfig.json",
                "frontend/vite.config.ts", "frontend/eslint.config.js", "frontend/src/components/FeatureGate.tsx",
                "backend/pom.xml", "backend/src/main/java/tn/x/auth/AuthService.java", "backend/src/main/java/tn/x/mail/MailService.java");
        Map<String, String> manifests = Map.of(
                "frontend/package.json", "{\"scripts\":{\"lint\":\"eslint .\",\"build\":\"tsc -b && vite build\"},"
                        + "\"dependencies\":{\"react\":\"^19.0.0\"},\"devDependencies\":{\"vite\":\"^6.0.0\",\"typescript\":\"^5.6.0\"}}",
                "backend/pom.xml", "<artifactId>spring-boot-starter-security</artifactId><artifactId>spring-boot-starter-test</artifactId>");
        CiRepoAnalyzer.Analysis a = CiRepoAnalyzer.analyze("Karimarouchi/Antigone_finance", "main", files, manifests, null, null);
        CiRepoAnalyzer.Part front = a.parts().get(1);
        assertThat(front.commands()).containsExactly("npm ci", "npm run lint", "npm run build");
        assertThat(front.warnings()).singleElement().asString().contains("eslint n'est pas dans les devDependencies");
        assertThat(a.prompt())
                .contains("npm install --package-lock-only --ignore-scripts")
                .contains("`frontend/vite.config.ts`")
                .contains("<Nom>.test.tsx")
                .contains("`vitest` ^3.0.0, `@testing-library/react` ^16.0.0")
                .contains("Problèmes déjà présents")
                .contains("spring-security-test")
                // exact repair of the missing ESLint, config only
                .contains("Réparation demandée").contains("`eslint` ^9.17.0").contains("`typescript-eslint` ^8.18.0")
                .contains("Crée `frontend/eslint.config.js` avec exactement ce contenu")
                .contains("export default tseslint.config(").contains("'@typescript-eslint/no-explicit-any': 'warn'")
                // build runs tsc: tests must type-check
                .contains("Le build de `frontend` lance `tsc`")
                // functional tests on both sides
                .contains("@testing-library/user-event").contains("Tests fonctionnels des contrôleurs")
                .contains("unitaires et fonctionnels");
        assertThat(CiRepoAnalyzer.eslintConfig(false)).contains("export default [").doesNotContain("tseslint");
    }

    @Test
    void promptCanBeLimitedToOnePartAndOneTheme() {
        List<String> files = List.of("backend/pom.xml", "backend/src/main/java/tn/x/auth/AuthService.java",
                "backend/src/main/java/tn/x/mail/MailService.java", "frontend/package.json");
        CiRepoAnalyzer.Analysis a = CiRepoAnalyzer.analyze("o/r", "main", files,
                Map.of("frontend/package.json", "{}"), java.util.Set.of("maven-backend"), "Auth");
        assertThat(a.prompt()).contains("Périmètre : uniquement ce qui concerne « auth »")
                .contains("AuthService.java").doesNotContain("MailService.java")
                .doesNotContain("### npm");
    }

    @Test
    void promptCarriesNoSourceCode() throws Exception {
        String prompt = coussin(List.of()).prompt();
        assertThat(prompt).doesNotContain("public class").doesNotContain("package com.");
    }

    @Test
    void classesThatAlreadyHaveATestAreNotTargetedAgain() {
        List<String> files = List.of("backend/pom.xml",
                "backend/src/main/java/tn/x/auth/AuthService.java", "backend/src/main/java/tn/x/mail/MailService.java",
                "backend/src/main/java/tn/x/auth/AuthController.java", "backend/src/test/java/tn/x/auth/AuthServiceTest.java",
                "backend/src/test/java/tn/x/auth/AuthControllerTests.java");
        CiRepoAnalyzer.Part back = CiRepoAnalyzer.analyze("o/r", "main", files,
                Map.of("backend/pom.xml", "<artifactId>spring-boot-starter-test</artifactId>")).parts().get(0);
        assertThat(back.hasTests()).isTrue();
        assertThat(back.targets()).containsExactly("backend/src/main/java/tn/x/mail/MailService.java");
    }
}
