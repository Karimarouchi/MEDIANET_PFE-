package com.medianet.service;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class AutoFixServiceTest {

    @Test
    void inferManifestFilenamePrefersNpmOverConflictingPomHint() throws Exception {
        AutoFixService service = new AutoFixService(null);

        String manifest = (String) invoke(service, "inferManifestFilename",
                new Class<?>[] { String.class, String.class, String.class },
                "axios", "Backend/pom.xml", "trivy");

        assertEquals("package.json", manifest);
    }

    @Test
    void tryProgrammaticFixDoesNotInjectNpmPackageIntoPom() throws Exception {
        AutoFixService service = new AutoFixService(null);
        String pom = "<project>\n" +
                "    <dependencies>\n" +
                "        <dependency>\n" +
                "            <groupId>org.springframework.boot</groupId>\n" +
                "            <artifactId>spring-boot-starter-web</artifactId>\n" +
                "        </dependency>\n" +
                "    </dependencies>\n" +
                "</project>\n";

        String fixed = (String) invoke(service, "tryProgrammaticFix",
                new Class<?>[] { String.class, String.class, String.class, String.class, String.class, String.class,
                        String.class },
                pom, "Backend/pom.xml", "axios", "axios", null, "1.13.6", "1.15.0");

        assertNull(fixed);
    }

    private Object invoke(Object target, String methodName, Class<?>[] parameterTypes, Object... args)
            throws Exception {
        Method method = target.getClass().getDeclaredMethod(methodName, parameterTypes);
        method.setAccessible(true);
        return method.invoke(target, args);
    }
}