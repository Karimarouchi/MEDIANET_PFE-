package com.medianet.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class FixVersionExtractionTest {

    private final FixVersionValidationService service = new FixVersionValidationService(null);

    @Test
    void extractsMavenVersionPreferringLastMatch() {
        String pom = """
                <project>
                  <dependency>
                    <groupId>org.apache.maven.plugins</groupId>
                    <artifactId>maven-surefire-plugin</artifactId>
                    <version>3.3.5</version>
                  </dependency>
                  <dependency>
                    <groupId>org.apache.maven.plugins</groupId>
                    <artifactId>maven-surefire-plugin</artifactId>
                    <version>4.0.14</version>
                  </dependency>
                </project>
                """;
        String v = service.extractVersionFromContent(
                pom, "org.apache.maven.plugins:maven-surefire-plugin", "pom.xml");
        assertEquals("4.0.14", v);
    }
}
