package com.medianet.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class ScanResultFilesTest {

    @Test
    void readsASmallRegularFile(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("compliance_profile.txt"), "cis_level1\n");
        assertThat(ScanResultFiles.readText(dir.toString(), "compliance_profile.txt", 256)).contains("cis_level1\n");
    }

    @Test
    void refusesTooLargeMissingOrEscapingNames(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("big.txt"), "x".repeat(300));
        assertThat(ScanResultFiles.readText(dir.toString(), "big.txt", 256)).isEmpty();
        assertThat(ScanResultFiles.readText(dir.toString(), "absent.txt", 256)).isEmpty();
        assertThat(ScanResultFiles.readText(dir.toString(), "../secret.txt", 256)).isEmpty();
    }

    /** A link planted by the scanned repository must never be read, and is removed after the scan. */
    @Test
    void refusesAndRemovesSymbolicLinks(@TempDir Path dir) throws Exception {
        Path outside = Files.writeString(dir.getParent().resolve("backend-secret-" + System.nanoTime() + ".txt"), "JWT_SECRET=x");
        Path results = Files.createDirectory(dir.resolve("results"));
        Path link = results.resolve("compliance_profile.txt");
        try {
            Files.createSymbolicLink(link, outside);
        } catch (Exception e) {
            assumeTrue(false, "symbolic links not allowed on this machine: " + e.getMessage());
        }
        try {
            assertThat(ScanResultFiles.readText(results.toString(), "compliance_profile.txt", 256)).isEmpty();
            assertThat(ScanResultFiles.removeLinksAndSpecialFiles(results.toString())).isEqualTo(1);
            assertThat(Files.exists(link, java.nio.file.LinkOption.NOFOLLOW_LINKS)).isFalse();
            assertThat(Files.readString(outside)).isEqualTo("JWT_SECRET=x"); // the target itself is untouched
        } finally {
            Files.deleteIfExists(outside);
        }
    }
}
