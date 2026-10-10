package com.medianet.service;

import com.medianet.entity.CveEntry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ResultParserServiceTest {

    @TempDir
    Path resultsDir;

    @Test
    void grypeRelatedVulnerabilitiesBecomeAliases() throws Exception {
        Files.writeString(resultsDir.resolve("grype.json"), """
                {
                  "matches": [{
                    "vulnerability": {
                      "id": "GHSA-w7jw-789q-xxxx",
                      "severity": "Critical",
                      "dataSource": "https://github.com/advisories/GHSA-w7jw-789q-xxxx"
                    },
                    "relatedVulnerabilities": [
                      { "id": "CVE-2026-9277", "namespace": "nvd:cpe" }
                    ],
                    "artifact": {
                      "name": "shell-quote",
                      "version": "1.8.3",
                      "type": "npm"
                    }
                  }]
                }
                """);
        Files.writeString(resultsDir.resolve("trivy.json"), """
                {
                  "Results": [{
                    "Target": "Frontend/package-lock.json",
                    "Type": "npm",
                    "Vulnerabilities": [{
                      "VulnerabilityID": "CVE-2026-9277",
                      "PkgName": "shell-quote",
                      "InstalledVersion": "1.8.3",
                      "Severity": "CRITICAL",
                      "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2026-9277",
                      "References": [
                        "https://github.com/advisories/GHSA-w7jw-789q-xxxx",
                        "https://nvd.nist.gov/vuln/detail/CVE-2026-9277"
                      ]
                    }]
                  }]
                }
                """);

        ResultParserService parser = new ResultParserService();
        List<CveEntry> parsed = parser.parseCves(resultsDir.toString());
        assertEquals(2, parsed.size());
        CveEntry grype = parsed.stream().filter(e -> "grype".equals(e.getSource())).findFirst().orElseThrow();
        CveEntry trivy = parsed.stream().filter(e -> "trivy".equals(e.getSource())).findFirst().orElseThrow();
        assertTrue(grype.getAliases().toUpperCase().contains("CVE-2026-9277"));
        assertTrue(trivy.getAliases().toUpperCase().contains("GHSA-W7JW-789Q-XXXX"));

        List<CveEntry> merged = new VulnerabilityNormalizer(new AdvisoryAliasCache()).normalize(parsed);
        assertEquals(1, merged.size());
        assertEquals("CVE-2026-9277", merged.get(0).getCanonicalId());
        assertEquals(2, merged.get(0).getConfirmedBy());
        assertTrue(merged.get(0).getAliases().toUpperCase().contains("GHSA-W7JW-789Q-XXXX"));
        assertFalse(merged.get(0).getAliases().toUpperCase().contains("CVE-2026-9277"));
    }

    @Test
    void npmAuditWithoutAdvisoryIdIsDropped() throws Exception {
        Files.writeString(resultsDir.resolve("npm-audit.json"), """
                {
                  "vulnerabilities": {
                    "css-select": {
                      "name": "css-select",
                      "severity": "high",
                      "via": ["css-select"],
                      "effects": [],
                      "range": "*"
                    }
                  }
                }
                """);
        List<CveEntry> parsed = new ResultParserService().parseCves(resultsDir.toString());
        assertTrue(parsed.stream().noneMatch(e -> (e.getCveId() != null && e.getCveId().startsWith("npm|"))
                || "css-select".equals(e.getPackageName())));
    }

    @Test
    void credSweeperFindingsAreMergedWithGitleaksByFileAndLine() throws Exception {
        Files.writeString(resultsDir.resolve("gitleaks.json"), """
                [{"RuleID":"generic-api-key","Description":"d","File":"/workspace/repo/config/env/development.js",
                  "StartLine":6,"EndLine":6,"Match":"zapApiKey: \\"abc\\"","Secret":"abc","Commit":"","Author":""}]
                """);
        Files.writeString(resultsDir.resolve("credsweeper.json"), """
                [
                 {"rule":"Key","severity":"high","ml_probability":0.9,"line_data_list":[
                   {"line":"  zapApiKey: \\"abc\\"","line_num":6,"path":"/workspace/repo/config/env/development.js","value":"abc"}]},
                 {"rule":"Password","severity":"medium","ml_probability":0.98,"line_data_list":[
                   {"line":"    password=\\"something-r@nd0m!\\",","line_num":40,"path":"/workspace/repo/app/tests/test_managers.py",
                    "value":"something-r@nd0m!"}]},
                 {"rule":"Secret","severity":"medium","line_data_list":[
                   {"line":"    password=\\"something-r@nd0m!\\",","line_num":40,"path":"/workspace/repo/app/tests/test_managers.py",
                    "value":"something-r@nd0m!"}]}
                ]
                """);

        List<com.medianet.entity.SecretFinding> secrets = new ResultParserService().parseSecrets(resultsDir.toString());

        assertEquals(2, secrets.size());  // same line seen by both = one finding; two rules on one line = one finding
        com.medianet.entity.SecretFinding both = secrets.get(0);
        assertEquals("gitleaks,credsweeper", both.getDetectors());
        assertEquals("abc", both.getRawSecret());
        com.medianet.entity.SecretFinding only = secrets.get(1);
        assertEquals("credsweeper", only.getDetectors());
        assertEquals("credsweeper:Password", only.getRuleId());
        assertEquals("something-r@nd0m!", only.getRawSecret());
        assertEquals(40, only.getStartLine());
    }

    @Test
    void missingOrBrokenCredSweeperReportLeavesGitleaksUntouched() throws Exception {
        Files.writeString(resultsDir.resolve("gitleaks.json"), """
                [{"RuleID":"private-key","File":"/w/a.key","StartLine":1,"EndLine":1,"Match":"-----BEGIN","Secret":"-----BEGIN"}]
                """);
        assertEquals(1, new ResultParserService().parseSecrets(resultsDir.toString()).size());
        Files.writeString(resultsDir.resolve("credsweeper.json"), "not json");
        List<com.medianet.entity.SecretFinding> secrets = new ResultParserService().parseSecrets(resultsDir.toString());
        assertEquals(1, secrets.size());
        assertEquals("gitleaks", secrets.get(0).getDetectors());
    }
}
