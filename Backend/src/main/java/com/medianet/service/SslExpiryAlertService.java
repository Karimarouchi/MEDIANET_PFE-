package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.entity.Client;
import com.medianet.entity.EmployeeClient;
import com.medianet.entity.NotificationType;
import com.medianet.entity.User;
import com.medianet.repository.AppNotificationRepo;
import com.medianet.repository.ClientRepo;
import com.medianet.repository.EmployeeClientRepo;
import com.medianet.repository.SslScanSnapshotRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Sends the inbox alert on the day the project chose, once per chosen date.
 */
@Service
public class SslExpiryAlertService {

    private static final Logger log = LoggerFactory.getLogger(SslExpiryAlertService.class);
    private static final DateTimeFormatter FRENCH = DateTimeFormatter.ofPattern("d MMMM yyyy", Locale.FRENCH);
    private static final Pattern YMD = Pattern.compile("^(\\d{4}-\\d{2}-\\d{2})");

    private final ClientRepo clientRepo;
    private final EmployeeClientRepo employeeClientRepo;
    private final AppNotificationRepo notificationRepo;
    private final NotificationService notificationService;
    private final SslScanSnapshotRepo snapshotRepo;
    private final ObjectMapper objectMapper;

    public SslExpiryAlertService(
            ClientRepo clientRepo,
            EmployeeClientRepo employeeClientRepo,
            AppNotificationRepo notificationRepo,
            NotificationService notificationService,
            SslScanSnapshotRepo snapshotRepo,
            ObjectMapper objectMapper) {
        this.clientRepo = clientRepo;
        this.employeeClientRepo = employeeClientRepo;
        this.notificationRepo = notificationRepo;
        this.notificationService = notificationService;
        this.snapshotRepo = snapshotRepo;
        this.objectMapper = objectMapper;
    }

    /** Expiry day of the certificate seen by the latest finished SSL scan of this domain, when it recorded one. */
    public Optional<LocalDate> certificateExpiry(String domain) {
        if (domain == null || domain.isBlank()) {
            return Optional.empty();
        }
        return snapshotRepo.findFirstByDomainIgnoreCaseAndScanStatusOrderByCreatedAtDesc(domain.trim(), "COMPLETED")
                .flatMap(snap -> expiryFromResultJson(objectMapper, snap.getResultJson()));
    }

    /** certificateDetail.notAfter first, then certNotAfterStr; only the leading yyyy-MM-dd is read. Package-private for tests. */
    static Optional<LocalDate> expiryFromResultJson(ObjectMapper mapper, String json) {
        if (json == null || json.isBlank()) {
            return Optional.empty();
        }
        try {
            JsonNode root = mapper.readTree(json);
            for (String raw : new String[] {
                    root.path("certificateDetail").path("notAfter").asText(""),
                    root.path("certNotAfterStr").asText("") }) {
                Matcher m = YMD.matcher(raw.trim());
                if (m.find()) {
                    return Optional.of(LocalDate.parse(m.group(1)));
                }
            }
        } catch (Exception e) {
            log.debug("Unreadable SSL snapshot: {}", e.getClass().getSimpleName());
        }
        return Optional.empty();
    }

    /**
     * Drop a previous alert, then send immediately when the chosen day is already reached.
     * The delete clears the persistence context, so the client is reloaded afterwards.
     */
    @Transactional
    public void refresh(Long clientId) {
        if (clientId == null) {
            return;
        }
        notificationRepo.deleteByRelatedRequestIdAndType(clientId, NotificationType.SSL_CERT_ALERT);
        clientRepo.findById(clientId).ifPresent(this::deliverIfDue);
    }

    @Scheduled(fixedDelay = 3_600_000, initialDelay = 120_000)
    @Transactional
    public void deliverDueAlerts() {
        LocalDate today = LocalDate.now();
        for (Client client : clientRepo.findAll()) {
            LocalDate alert = client.getSslAlertDate();
            if (alert == null || alert.isAfter(today) || alert.equals(client.getSslAlertNotifiedOn())) {
                continue;
            }
            deliverIfDue(client);
        }
    }

    private void deliverIfDue(Client client) {
        LocalDate alert = client.getSslAlertDate();
        if (alert == null || alert.isAfter(LocalDate.now())) {
            return;
        }
        if (alert.equals(client.getSslAlertNotifiedOn())) {
            return;
        }
        String domain = client.getDomainName() == null || client.getDomainName().isBlank()
                ? "ce projet"
                : client.getDomainName().trim();
        String title = "Alerte SSL · " + domain;
        String message = alertMessage(domain, client.getName(), alert,
                certificateExpiry(client.getDomainName()).orElse(null), LocalDate.now());
        String link = "/projects/" + client.getId();
        int sent = 0;
        for (User recipient : recipients(client).values()) {
            notificationService.notifyUser(recipient, NotificationType.SSL_CERT_ALERT, title, message, link, client.getId());
            sent++;
        }
        client.setSslAlertNotifiedOn(alert);
        clientRepo.save(client);
        log.info("SSL alert sent for client {} domain {} recipients {}", client.getId(), domain, sent);
    }

    /** Package-private for tests. */
    static String alertMessage(String domain, String project, LocalDate alert, LocalDate expiry, LocalDate today) {
        String head = "Vous aviez choisi d'être prévenu le " + alert.format(FRENCH) + ". ";
        if (expiry == null) {
            return head + "Le dernier scan SSL de " + domain + " n'indique pas de date d'expiration : "
                    + "relancez un scan SSL depuis le projet " + project + ".";
        }
        long days = ChronoUnit.DAYS.between(today, expiry);
        String when = days < 0 ? "a expiré le " + expiry.format(FRENCH)
                : days == 0 ? "expire aujourd'hui (" + expiry.format(FRENCH) + ")"
                : "expire le " + expiry.format(FRENCH) + ", dans " + days + (days == 1 ? " jour" : " jours");
        return head + "Le certificat de " + domain + " " + when
                + ". Renouvelez-le puis relancez un scan SSL du projet " + project + ".";
    }

    private Map<Long, User> recipients(Client client) {
        Map<Long, User> byId = new LinkedHashMap<>();
        User creator = client.getCreatedBy();
        if (creator != null && creator.getId() != null && !Boolean.TRUE.equals(creator.getSuspended())) {
            byId.put(creator.getId(), creator);
        }
        for (EmployeeClient link : employeeClientRepo.findByClient_Id(client.getId())) {
            User employee = link.getEmployee();
            if (employee != null && employee.getId() != null && !Boolean.TRUE.equals(employee.getSuspended())) {
                byId.put(employee.getId(), employee);
            }
        }
        return byId;
    }
}
