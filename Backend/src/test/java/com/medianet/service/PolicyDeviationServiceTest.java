package com.medianet.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PolicyDeviationServiceTest {

    @Test
    void versionsEquivalent_stripsPrefixAndIgnoresCase() {
        assertTrue(PolicyDeviationService.versionsEquivalent("4.0.4", "4.0.4"));
        assertTrue(PolicyDeviationService.versionsEquivalent("v4.0.4", "4.0.4"));
        assertTrue(PolicyDeviationService.versionsEquivalent("4.0.4", "V4.0.4"));
        assertFalse(PolicyDeviationService.versionsEquivalent("4.0.4", "4.0.14"));
        assertFalse(PolicyDeviationService.versionsEquivalent("4.0.4", null));
        assertFalse(PolicyDeviationService.versionsEquivalent(null, "4.0.4"));
    }

    @Test
    void deviationDetectedWhenChosenDiffersFromChef() {
        String official = "4.0.4";
        String chosenFromContent = "4.0.14";
        String chosenFromBody = "4.0.4"; // misleading body — content wins in controller
        String chosen = firstNonBlank(chosenFromContent, chosenFromBody);
        boolean deviation = official != null
                && chosen != null && !chosen.isBlank()
                && !PolicyDeviationService.versionsEquivalent(official, chosen);
        assertTrue(deviation);
        assertEquals("4.0.14", chosen);
    }

    @Test
    void noDeviationWhenAlignedWithChef() {
        String official = "4.0.4";
        String chosen = "v4.0.4";
        boolean deviation = !PolicyDeviationService.versionsEquivalent(official, chosen);
        assertFalse(deviation);
    }

    private static String firstNonBlank(String... values) {
        for (String v : values) {
            if (v != null && !v.isBlank()) return v.trim();
        }
        return null;
    }
}
