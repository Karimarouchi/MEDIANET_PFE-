package com.medianet.service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

/** Locates the {@code ml/} directory and its Python interpreter (shared by the ML sidecar services). */
final class MlPaths {

    private MlPaths() {
    }

    static Path resolveMlDir(String configured) {
        if (configured != null && !configured.isBlank()) {
            return Path.of(configured).toAbsolutePath().normalize();
        }
        Path cwd = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize();
        Path sibling = cwd.resolve("ml");
        if (Files.isDirectory(sibling)) {
            return sibling;
        }
        return cwd.getParent() != null ? cwd.getParent().resolve("ml").normalize() : sibling;
    }

    static Path resolvePython(String configured, Path mlDir) {
        if (configured != null && !configured.isBlank()) {
            return Path.of(configured);
        }
        boolean windows = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
        Path venv = windows
                ? mlDir.resolve("venv").resolve("Scripts").resolve("python.exe")
                : mlDir.resolve("venv").resolve("bin").resolve("python");
        if (Files.isRegularFile(venv)) {
            return venv;
        }
        return Path.of(windows ? "python.exe" : "python");
    }
}
