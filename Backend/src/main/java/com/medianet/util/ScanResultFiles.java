package com.medianet.util;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Optional;

/**
 * Reads files the scanner container wrote into a scan's results directory.
 *
 * That directory is writable by the code of the scanned repository (build tools run inside the container), so a
 * file there can be a symbolic link to a backend file such as {@code /proc/self/environ}. Only regular files that
 * are not links, sit directly in the results directory and stay under a size cap are read.
 */
public final class ScanResultFiles {

    private ScanResultFiles() {
    }

    /**
     * Deletes every symbolic link and special file under the results directory (without following links), so the
     * parsers that run afterwards only ever see regular files the container wrote. Returns how many were removed.
     */
    public static int removeLinksAndSpecialFiles(String resultsDir) {
        if (resultsDir == null || resultsDir.isBlank()) {
            return 0;
        }
        Path root = Path.of(resultsDir);
        if (Files.isSymbolicLink(root) || !Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
            return 0;
        }
        int[] removed = {0};
        try (var walk = Files.walk(root)) { // Files.walk does not follow links by default
            walk.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                try {
                    BasicFileAttributes a = Files.readAttributes(p, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                    if (a.isSymbolicLink() || a.isOther()) {
                        Files.delete(p);
                        removed[0]++;
                    }
                } catch (IOException e) {
                    // left in place: readText and the SSL reader refuse links anyway
                }
            });
        } catch (IOException e) {
            return removed[0];
        }
        return removed[0];
    }

    /** Text of {@code resultsDir/name}, or empty when missing, a link, not a regular file, or larger than maxBytes. */
    public static Optional<String> readText(String resultsDir, String name, int maxBytes) {
        if (resultsDir == null || resultsDir.isBlank() || name == null || name.contains("/") || name.contains("\\")
                || name.contains("..")) {
            return Optional.empty();
        }
        Path dir = Path.of(resultsDir);
        Path file = dir.resolve(name);
        try {
            if (Files.isSymbolicLink(dir) || Files.isSymbolicLink(file)) {
                return Optional.empty();
            }
            BasicFileAttributes attrs = Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!attrs.isRegularFile() || attrs.size() > maxBytes) {
                return Optional.empty();
            }
            try (InputStream in = Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS)) {
                byte[] bytes = in.readNBytes(maxBytes + 1);
                if (bytes.length > maxBytes) {
                    return Optional.empty();
                }
                return Optional.of(new String(bytes, StandardCharsets.UTF_8));
            }
        } catch (IOException | UnsupportedOperationException e) {
            return Optional.empty();
        }
    }
}
