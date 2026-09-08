package com.medianet.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AiGatewayServiceTest {

    @Test
    void gemini403DoesNotMentionXai() {
        String msg = AiGatewayService.describeKeyError("GEMINI", "gemini-3.5-flash-lite", 403,
                "{\"error\":{\"status\":\"PERMISSION_DENIED\"}}");
        assertTrue(msg.contains("GEMINI"));
        assertTrue(msg.contains("Auto"));
        assertFalse(msg.toLowerCase().contains("console.x.ai"));
        assertFalse(msg.toLowerCase().contains("grok"));
    }

    @Test
    void grok403MentionsXaiCredits() {
        String msg = AiGatewayService.describeKeyError("GROK", "grok-4.6", 403, "forbidden");
        assertTrue(msg.contains("console.x.ai"));
    }

    @Test
    void geminiModelNotFoundTellsUserToUseAuto() {
        String msg = AiGatewayService.describeKeyError("GEMINI", "gemini-2.0-flash", 404, "not_found");
        assertTrue(msg.toLowerCase().contains("auto"));
        assertFalse(msg.toLowerCase().contains("console.x.ai"));
    }
}
