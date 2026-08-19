package com.medianet.service;

import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GitLabServiceTest {

    @Test
    void encodeGitlabPathEncodesSlashOnceAsPercent2F() {
        String encoded = GitLabService.encodeGitlabPath("antigone-agency/pfe-mediannet");
        assertEquals("antigone-agency%2Fpfe-mediannet", encoded);
        assertFalse(encoded.contains("%252F"));
    }

    @Test
    void encodeGitlabPathUsesPercent20ForSpacesNotPlus() {
        assertEquals("Pfe%20mediannet", GitLabService.encodeGitlabPath("Pfe mediannet"));
        assertFalse(GitLabService.encodeGitlabPath("Pfe mediannet").contains("+"));
    }

    @Test
    void normalizeProjectPathKeepsPathSlugFromCloneAndWebUrls() {
        assertEquals("antigone-agency/pfe-mediannet",
                GitLabService.normalizeProjectPath("https://gitlab.com/antigone-agency/pfe-mediannet.git"));
        assertEquals("antigone-agency/pfe-mediannet",
                GitLabService.normalizeProjectPath("https://gitlab.com/antigone-agency/pfe-mediannet/-/tree/main"));
        assertEquals("antigone-agency/pfe-mediannet",
                GitLabService.normalizeProjectPath("git@gitlab.com:antigone-agency/pfe-mediannet.git"));
        assertEquals("antigone-agency/pfe-mediannet",
                GitLabService.normalizeProjectPath("antigone-agency/pfe-mediannet"));
    }

    @Test
    void projectUriDoesNotDoubleEncodeNamespacedPath() {
        URI uri = GitLabService.projectUri("https://gitlab.com", "antigone-agency/pfe-mediannet");
        assertEquals("https://gitlab.com/api/v4/projects/antigone-agency%2Fpfe-mediannet", uri.toString());
        assertFalse(uri.toString().contains("%252F"));
        assertTrue(uri.toString().contains("%2F"));
    }

    @Test
    void repositoryFileUriEncodesProjectAndFileSlashesOnce() {
        URI uri = GitLabService.repositoryFileUri(
                "https://gitlab.com",
                "antigone-agency/pfe-mediannet",
                "Backend/pom.xml",
                "main");
        assertEquals(
                "https://gitlab.com/api/v4/projects/antigone-agency%2Fpfe-mediannet/repository/files/Backend%2Fpom.xml?ref=main",
                uri.toString());
        assertFalse(uri.toString().contains("%252F"));
    }

    @Test
    void numericProjectIdIsNotEncodedAsPath() {
        URI uri = GitLabService.projectUri("https://gitlab.com", "12345");
        assertEquals("https://gitlab.com/api/v4/projects/12345", uri.toString());
    }
}
