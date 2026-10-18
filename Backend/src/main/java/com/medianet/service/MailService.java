package com.medianet.service;

import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;

/**
 * Sends Vulnix e-mails over SMTP (Spring Mail, the Java counterpart of PHPMailer). Configured in
 * config/secrets.local.properties, e.g. Gmail: spring.mail.host=smtp.gmail.com, port 587, STARTTLS, the account and an
 * application password. Without spring.mail.host nothing is sent and the bell still gets every alert.
 */
@Service
public class MailService {

    private static final Logger log = LoggerFactory.getLogger(MailService.class);

    private final ObjectProvider<JavaMailSender> sender;
    private final String host;
    private final String from;
    private final String fromName;
    private final String appUrl;

    public MailService(ObjectProvider<JavaMailSender> sender,
            @Value("${spring.mail.host:}") String host,
            @Value("${vulnix.mail.from:${spring.mail.username:}}") String from,
            @Value("${vulnix.mail.from-name:Vulnix}") String fromName,
            @Value("${github.oauth.frontend-url:http://localhost:3000}") String appUrl) {
        this.sender = sender;
        this.host = host == null ? "" : host.trim();
        this.from = from == null ? "" : from.trim();
        this.fromName = fromName;
        this.appUrl = appUrl.replaceAll("/+$", "");
    }

    public boolean isConfigured() {
        return !host.isEmpty() && !from.isEmpty() && sender.getIfAvailable() != null;
    }

    /** Best effort: a mail problem is logged, never breaks the deploy that triggered it. */
    public boolean send(String to, String subject, String text, String link) {
        return trySend(to, subject, text, link) == null;
    }

    /** Null when sent, otherwise why not (shown by the "test e-mail" button). */
    public String trySend(String to, String subject, String text, String link) {
        if (!isConfigured()) {
            return "SMTP non configuré (spring.mail.host / spring.mail.username dans config/secrets.local.properties).";
        }
        if (to == null || !to.matches("[^@\\s]+@[^@\\s]+\\.[^@\\s]+")) {
            return "Adresse e-mail invalide.";
        }
        try {
            JavaMailSender mail = sender.getObject();
            MimeMessage message = mail.createMimeMessage();
            MimeMessageHelper h = new MimeMessageHelper(message, false, StandardCharsets.UTF_8.name());
            h.setFrom(new InternetAddress(from, fromName, StandardCharsets.UTF_8.name()));
            h.setTo(to);
            h.setSubject(subject);
            h.setText(body(text, link), false);
            mail.send(message);
            return null;
        } catch (Exception e) {
            log.warn("[Mail] not sent to {}: {}", mask(to), e.getMessage());
            String reason = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            if (reason.contains("535") || reason.toLowerCase().contains("authentication")) {
                return "Gmail refuse l'identifiant ou le mot de passe d'application.";
            }
            return "Envoi impossible : " + (reason.length() > 160 ? reason.substring(0, 160) + "…" : reason);
        }
    }

    /** Plain-text body with the absolute link to Vulnix. Package-private for tests. */
    String body(String text, String link) {
        StringBuilder b = new StringBuilder(text == null ? "" : text.strip()).append("\n\n");
        if (link != null && !link.isBlank()) {
            b.append("Ouvrir dans Vulnix : ").append(link.startsWith("http") ? link : appUrl + link).append("\n\n");
        }
        b.append("—\nVulnix · notification automatique. Pour ne plus recevoir ces e-mails : Profil > Notifications par e-mail.");
        return b.toString();
    }

    static String mask(String email) {
        int at = email.indexOf('@');
        return at <= 1 ? "***" : email.charAt(0) + "***" + email.substring(at);
    }
}
