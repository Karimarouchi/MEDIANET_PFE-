package com.medianet;

import com.medianet.repository.CveEntryRepo;
import com.medianet.service.CisaKevService;
import com.medianet.service.EpssService;
import com.medianet.service.ExploitDbService;
import com.medianet.service.NvdEnrichmentService;
import com.medianet.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableAsync
@EnableScheduling
public class MedianetApplication {

    private static final Logger log = LoggerFactory.getLogger(MedianetApplication.class);

    private final CveEntryRepo cveEntryRepo;
    private final NvdEnrichmentService nvdEnrichmentService;
    private final ExploitDbService exploitDbService;
    private final CisaKevService cisaKevService;
    private final EpssService epssService;
    private final UserService userService;

    public MedianetApplication(CveEntryRepo cveEntryRepo, NvdEnrichmentService nvdEnrichmentService,
            ExploitDbService exploitDbService, CisaKevService cisaKevService, EpssService epssService,
            UserService userService) {
        this.cveEntryRepo = cveEntryRepo;
        this.nvdEnrichmentService = nvdEnrichmentService;
        this.exploitDbService = exploitDbService;
        this.cisaKevService = cisaKevService;
        this.epssService = epssService;
        this.userService = userService;
    }

    public static void main(String[] args) {
        SpringApplication.run(MedianetApplication.class, args);
    }

    /**
     * Au démarrage : si des CVEs sont sans score ou severity UNKNOWN,
     * lancer l'enrichissement en arrière-plan automatiquement.
     */
    @EventListener(ApplicationReadyEvent.class)
    public void onReady() {
        userService.normalizeLegacyClientAccessModel();
        userService.ensureRoleCatalog();
        userService.ensureBootstrapAdminAccount();
        long missingCount = cveEntryRepo.countMissingEnrichment();
        if (missingCount > 0) {
            log.info("[STARTUP] {} CVEs sans enrichissement détectés — lancement auto...", missingCount);
            nvdEnrichmentService.enrichAllMissingCves();
        } else {
            log.info("[STARTUP] Tous les CVEs sont déjà enrichis.");
        }
        // Enrichissement rétroactif Exploit-DB pour les CVEs déjà en base
        log.info("[STARTUP] Lancement de l'enrichissement Exploit-DB rétroactif...");
        exploitDbService.enrichAllExistingCves();
        // Enrichissement rétroactif CISA KEV pour les CVEs déjà en base
        log.info("[STARTUP] Lancement de l'enrichissement CISA KEV rétroactif...");
        cisaKevService.enrichAllExistingCves();
        // Enrichissement rétroactif EPSS pour les CVEs déjà en base
        log.info("[STARTUP] Lancement de l'enrichissement EPSS rétroactif...");
        epssService.enrichAllExistingCves();
    }
}
