package com.medianet.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CisaKevServiceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void parsesOfficialCisaFieldNames() throws Exception {
        var root = MAPPER.readTree("""
                {"vulnerabilities":[
                  {"cveID":"CVE-2021-44228","dateAdded":"2021-12-10","knownRansomwareCampaignUse":"Known"},
                  {"cveID":"cve-2023-44487","dateAdded":"2023-10-10","knownRansomwareCampaignUse":"Unknown"}
                ]}
                """);
        var index = CisaKevService.parseCatalog(root);
        assertNotNull(index);
        assertEquals(2, index.size());
        assertTrue(index.containsKey("CVE-2021-44228"));
        assertTrue(index.get("CVE-2021-44228").ransomware());
        assertEquals("2021-12-10", index.get("CVE-2021-44228").dateAdded());
        assertTrue(index.containsKey("CVE-2023-44487"));
        assertFalse(index.get("CVE-2023-44487").ransomware());
    }

    @Test
    void rejectsPayloadWithoutVulnerabilitiesArray() throws Exception {
        assertNull(CisaKevService.parseCatalog(MAPPER.readTree("{\"catalogVersion\":\"2024\"}")));
    }
}
