package com.medianet.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/** The Dependency-Check cache may sit on a removable disk: an unreachable folder must not be mounted. */
class ScanServiceDcCacheTest {

    @Test
    void anExistingFolderIsUsable(@TempDir Path dir) {
        assertTrue(ScanService.ensureDirectory(dir.toString()));
    }

    @Test
    void aMissingFolderIsCreated(@TempDir Path dir) {
        Path cache = dir.resolve("MEDIANET ML").resolve("dc-cache");
        assertTrue(ScanService.ensureDirectory(cache.toString()));
        assertTrue(Files.isDirectory(cache));
    }

    @Test
    void aPathBlockedByAFileIsNotUsable(@TempDir Path dir) throws Exception {
        Path file = Files.writeString(dir.resolve("not-a-folder"), "x");
        assertFalse(ScanService.ensureDirectory(file.resolve("dc-cache").toString()));
    }

    @Test
    void anUnsetPathIsNotUsable() {
        assertFalse(ScanService.ensureDirectory(null));
        assertFalse(ScanService.ensureDirectory("  "));
    }
}
