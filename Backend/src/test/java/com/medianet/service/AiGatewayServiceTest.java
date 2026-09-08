package com.medianet.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AiGatewayServiceTest {

    @Test
    void gemini403DoesNotMentionXai() {
        String msg = AiGatewayService.describeKeyError("GEMINI", "gemini-3.5-flash-lite", 403,
                "{\"error\":{\"status\":\"PERMISSION_DENIED\",\"message\":\"API keys are not enabled by default. Please restrict your key.\"}}");
        assertTrue(msg.contains("GEMINI"));
        assertTrue(msg.contains("Gemini API"));
        assertTrue(msg.contains("Google :"));
        assertFalse(msg.toLowerCase().contains("console.x.ai"));
        assertFalse(msg.toLowerCase().contains("grok"));
    }

    @Test
    void geminiSuspendedProjectIsExplained() {
        String msg = AiGatewayService.describeKeyError("GEMINI", "", 403,
                "{\"error\":{\"message\":\"Permission denied: Consumer has been suspended.\",\"status\":\"PERMISSION_DENIED\",\"details\":[{\"reason\":\"CONSUMER_SUSPENDED\"}]}}");
        assertTrue(msg.contains("CONSUMER_SUSPENDED") || msg.toLowerCase().contains("suspendu"));
        assertFalse(msg.toLowerCase().contains("console.x.ai"));
    }

    @Test
    void aqKeysAreNotClassicQueryKeys() {
        assertFalse(AiGatewayService.isClassicGoogleAiKey("AQ.example"));
        assertTrue(AiGatewayService.isClassicGoogleAiKey("AIzaSyDummy"));
    }

    @Test
    void grok403MentionsXaiCredits() {
        String msg = AiGatewayService.describeKeyError("GROK", "grok-4.6", 403, "forbidden");
        assertTrue(msg.contains("console.x.ai"));
        assertFalse(msg.toLowerCase().contains("console.groq.com"));
    }

    @Test
    void groq403MentionsGroqConsoleNotXai() {
        String msg = AiGatewayService.describeKeyError("GROQ", "openai/gpt-oss-20b", 403, "forbidden");
        assertTrue(msg.contains("console.groq.com"));
        assertTrue(msg.contains("gsk_"));
        assertFalse(msg.contains("console.x.ai"));
    }

    @Test
    void groqModelNotFoundTellsUserToUseAuto() {
        String msg = AiGatewayService.describeKeyError("GROQ", "llama-3.3-70b-versatile", 404, "model_not_found");
        assertTrue(msg.toLowerCase().contains("gpt-oss-20b"));
        assertFalse(msg.contains("console.x.ai"));
    }

    @Test
    void geminiModelNotFoundTellsUserToUseAuto() {
        String msg = AiGatewayService.describeKeyError("GEMINI", "gemini-2.0-flash", 404, "not_found");
        assertTrue(msg.toLowerCase().contains("auto"));
        assertFalse(msg.toLowerCase().contains("console.x.ai"));
    }
}
