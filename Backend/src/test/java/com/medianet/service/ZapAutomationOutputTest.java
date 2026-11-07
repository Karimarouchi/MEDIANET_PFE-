package com.medianet.service;

import com.medianet.entity.CveEntry;
import com.medianet.entity.FindingKind;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Real output of ZAP's Automation Framework run (spider + passive scan, traditional-json report) against a test web
 * server: the proposed replacement for the missing zap-baseline.py must be readable by the existing ZAP parser.
 */
class ZapAutomationOutputTest {

    @Test
    void theAutomationFrameworkReportIsParsedAsDast() throws Exception {
        String dir = new File(getClass().getResource("/scanner-real-zap").toURI()).getPath();
        List<CveEntry> entries = new VulnerabilityNormalizer(new AdvisoryAliasCache())
                .normalize(new ResultParserService().parseCves(dir));
        assertEquals(6, entries.size());
        assertTrue(entries.stream().allMatch(e -> e.getFindingKind() == FindingKind.DAST));
        assertTrue(entries.stream().allMatch(e -> e.getCveId().startsWith("ZAP-")));
        assertTrue(entries.stream().allMatch(e -> e.getFilePath() != null && e.getFilePath().startsWith("http")));
        assertTrue(entries.stream().anyMatch(e -> "MEDIUM".equals(e.getSeverity())));
        assertTrue(entries.stream().anyMatch(e -> "LOW".equals(e.getSeverity())));
    }

    @Test
    void theReferenceFitsItsColumn() throws Exception {
        String dir = new File(getClass().getResource("/scanner-real-zap").toURI()).getPath();
        List<CveEntry> entries = new ResultParserService().parseCves(dir);
        // The real report has references of 369 characters; the column holds 255 and a longer value made the whole
        // scan import fail (the scan stayed RUNNING).
        assertTrue(entries.stream().allMatch(e -> e.getDataSource() == null || e.getDataSource().length() <= 255));
        assertTrue(entries.stream().anyMatch(e -> e.getDataSource() != null && e.getDataSource().startsWith("https://")));
    }

    @Test
    void firstUrlKeepsTheFirstLinkOfAnHtmlReference() {
        assertEquals("https://a.example/x", ResultParserService.firstUrl("<p>https://a.example/x</p><p>https://b.example/y</p>"));
        assertEquals("plain text", ResultParserService.firstUrl("plain text"));
        assertNull(ResultParserService.firstUrl("  "));
        assertEquals(255, ResultParserService.firstUrl("x".repeat(400)).length());
    }
}
