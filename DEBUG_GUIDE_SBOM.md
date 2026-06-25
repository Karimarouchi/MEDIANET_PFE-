# 🛠️ Guide de débogage SBOM - Étape par étape

## **1. Première étape : Vérifier que le SBOM existe**

### **Commande à exécuter après un scan**

```bash
# Vérifiez que le SBOM est généré par le scanner Docker
ls -la scan-results/<UUID>/sbom*

# Devrait montrer:
# sbom.cdx.json   (CycloneDX format) - PRÉFÉRÉ
# sbom.syft.json  (Syft format) - Accepté aussi
# sbom.json       (Format générique)
```

### **Si aucun fichier SBOM:**

```
❌ PROBLÈME: Le Docker scanner n'a PAS généré de SBOM
├─ Vérifier: devsecops-pipeline.yml contient-il la génération SBOM?
└─ Solution: Ajouter des outils génération SBOM (cdxgen, syft, etc.)
```

### **Si SBOM existe:**

```
✓ Vérifier le contenu:
   - Combien de composants? (jq '.components | length' sbom.cdx.json)
   - Contient jjwt-api, spring-boot-*? (jq '.components[] | .name')
   - Les versions matchent-elles pom.xml?
```

---

## **2. Deuxième étape : Lancer un scan et regarder les logs**

### **A. Démarrer le backend et frontend**

```bash
# Terminal 1: Backend (Spring Boot)
cd Backend
./mvnw.cmd spring-boot:run

# Terminal 2: Frontend (React)
cd Frontend
npm start
```

### **B. Lancer un scan via l'UI**

```
1. Allez à Vulnix dashboard
2. Click "Nouveau scan"
3. Choisissez "Local Repository"
4. Attendez que le scan finisse (~2 min)
5. Regardez les logs dans Terminal 1:

   Logs attendus:
   [SBOM] ✓ SBOM parsed successfully with 42 components
   [SBOM] ✓ CVE-2021-1234 → DIRECT (confidence=HIGH)
   [SBOM] ✗ CVE-2021-5678 → UNKNOWN (no component match)
   [SBOM] Enrichment summary: 35/80 resolved | 45 UNKNOWN | 0 errors
   [SBOM] Success rate: 43%
```

### **C. Logs de problème à chercher**

#### **Problème 1: SBOM absent**

```
[SBOM] ⚠️ No SBOM data available — all 80 CVEs will get UNKNOWN/LOW confidence
[SBOM] Check: Does /path/to/scan-results/<UUID> contain sbom.*.json?

→ Action: Vérifier que scanner génère SBOM
```

#### **Problème 2: SBOM parsé mais peu de matches**

```
[SBOM] ✓ SBOM parsed successfully with 42 components
[SBOM] Enrichment summary: 5/80 resolved | 75 UNKNOWN | 0 errors
[SBOM] Success rate: 6%

→ Action: Investiguer pourquoi les noms/versions ne matchent pas
```

#### **Problème 3: Erreurs lors de l'enrichissement**

```
[SBOM] Failed to enrich CVE CVE-2021-1234: NullPointerException
[SBOM] Failed to enrich CVE CVE-2021-5678: Index out of bounds

→ Action: Vérifier bug dans SbomEnrichmentService
```

---

## **3. Troisième étape : Activer le DEBUG logging**

### **Modifier logging en application.properties**

```properties
# application.properties
logging.level.com.medianet.service.SbomEnrichmentService=DEBUG
logging.level.com.medianet.service.SbomParserService=DEBUG
logging.level.com.medianet.service.DependencyGraphService=DEBUG
logging.level.com.medianet.service.ResultParserService=DEBUG
```

### **Relancer le backend avec DEBUG activé**

```bash
./mvnw.cmd spring-boot:run

# Logs attendus pour CHAQUE CVE:
[SBOM] CVE-2021-1234 | Found component: jjwt-api | purl=yes matched
[SBOM] CVE-2021-1234 → DIRECT | depth=1 | confidence=HIGH | path=root → jjwt-api | module=Backend

[SBOM] CVE-2021-5678 | No component found | attempted: purl=null bomRef=null name=spring-boot-web eco=maven
[SBOM] CVE-2021-5678 → UNKNOWN | depth=0 | confidence=LOW | path=null | module=Backend
```

---

## **4. Lire les fichiers de résultats du scan**

### **A. Vérifier les CVEs détectées par Grype/Trivy**

```bash
# Lister les CVEs détectés
jq '.[] | {cveId, packageName, packageVersion, ecosystem, purl}' \
   Backend/target/cves.json | head -30

# Devrait montrer:
{
  "cveId": "CVE-2021-1234",
  "packageName": "jjwt-api",
  "packageVersion": "0.12.5",
  "ecosystem": "maven",
  "purl": "pkg:maven/io.jsonwebtoken:jjwt-api@0.12.5"  ← KEY FIELD
}
```

### **B. Vérifier les composants du SBOM**

```bash
# Lister les composants SBOM
jq '.components[] | {name, version, purl, type}' \
   scan-results/<UUID>/sbom.cdx.json | head -20

# Devrait montrer:
{
  "name": "jjwt-api",
  "version": "0.12.5",
  "purl": "pkg:maven/io.jsonwebtoken:jjwt-api@0.12.5",
  "type": "library"
}
```

### **C. Comparaison manuelle**

```bash
# CVE de Grype:
# {cveId: "CVE-2021-1234", packageName: "jjwt-api", version: "0.12.5"}

# Composant SBOM:
# {name: "jjwt-api", version: "0.12.5", purl: "pkg:maven/io.jsonwebtoken:jjwt-api@0.12.5"}

# Matching doit retourner TRUE car:
# ✓ purl match (si présent)
# ✓ name+version+eco match
```

---

## **5. Cas à investiguer**

### **Cas A: Version = UNKNOWN**

```bash
# Chercher dans Grype output:
jq '.[] | select(.packageVersion == null or .packageVersion == "")' \
   Backend/target/cves.json

# Si beaucoup de null/empty:
# → Le scanner ne peut pas déterminer les versions
# → SBOM doit avoir les vraies versions sinon matching échoue
```

**Pourquoi ça arrive:**

- Maven/npm utilisent des dépendances transitives avec versions héritées
- Grype/Trivy trouvent le package mais pas la version installée finale
- pom.xml n'a pas la version explicite pour les starter packages

**Solution:**

- Générer SBOM avec `mvn cyclonedx:makeBom` (donne vraies versions)
- Ou chercher version dans `target/dependency-report.json` généré par Maven

---

### **Cas B: Noms ne matchent pas**

```bash
# CVE de Grype:
# "jjwt-api"

# SBOM:
# "io.jsonwebtoken:jjwt-api"

# → Pas de match car noms différents
# → Besoin de normaliser: extraire "jjwt-api" du PURL
```

**Vérifier dans code:**

```java
// SbomParserService.java
SbomComponent comp = parsedComponent;
// comp.name devrait être "jjwt-api" SEUL
// pas "io.jsonwebtoken:jjwt-api"

// Si c'est le nom complet, fallback matching échoue
// Car CVE a packageName = "jjwt-api"
```

---

### **Cas C: PURL ne match pas**

```bash
# CVE Grype:
# "pkg:maven/io.jsonwebtoken:jjwt-api@0.12.5"

# SBOM:
# "pkg:maven/io.jsonwebtoken/jjwt-api@0.12.5"

# Différence: / vs : dans le path
# → PURL normalization doit gérer ça
```

**Vérifier SbomParserService:**

```java
static String normalizePurl(String purl) {
    // Doit normaliser le path Maven
    // /io.jsonwebtoken:jjwt-api = /io/jsonwebtoken/jjwt-api
    // Ou l'inverse
}
```

---

## **6. Requête SQL de debug**

### **Voir les CVEs enrichies dans PostgreSQL**

```sql
-- Connexion à PostgreSQL (même terminal ou autre)
psql -U medianet_user -d medianet_db

-- Voir CVEs avec SBOM data
SELECT
    cve_id,
    package_name,
    component_name,
    direct_or_transitive,
    dependency_confidence,
    dependency_path
FROM cve_entries
WHERE component_name IS NOT NULL
   OR direct_or_transitive IS NOT NULL
LIMIT 20;

-- Devrait montrer:
-- CVE-2021-1234 | jjwt-api | jjwt-api | DIRECT | HIGH | root → jjwt-api@0.12.5
-- CVE-2021-5678 | spring-web | NULL | UNKNOWN | LOW | NULL

-- Si tout est NULL ou UNKNOWN:
-- → Enrichissement n'a pas fonctionné
```

### **Voir les résultats de scan**

```sql
-- Voir le dernier scan
SELECT
    id,
    project_name,
    created_at,
    status,
    cve_count
FROM scans
ORDER BY created_at DESC
LIMIT 5;

-- Compter les DIRECT vs TRANSITIVE
SELECT
    direct_or_transitive,
    COUNT(*) as count
FROM cve_entries
WHERE scan_id = <your_scan_id>
GROUP BY direct_or_transitive;

-- Résultat attendu:
-- DIRECT   | 10
-- TRANSITIVE | 20
-- UNKNOWN  | 50
```

---

## **7. Checklist finale de debug**

Pour chaque problème, suivez cette checklist:

### **🔴 Success rate < 10%**

- [ ] SBOM existe? (`ls scan-results/*/sbom*`)
- [ ] SBOM contient composants? (`jq '.components | length'`)
- [ ] Grype extrait purl? (`jq '.purl'`)
- [ ] Trivy extrait version? (`jq '.InstalledVersion'`)
- [ ] Noms matchent? (comparer manuellement)

### **🟡 Success rate 10-50%**

- [ ] Versions parfois null? (investiguer Cas A)
- [ ] Noms partiellement matchés? (investiguer Cas B)
- [ ] PURL format différent? (investiguer Cas C)

### **🟢 Success rate > 50%**

- [ ] ✓ Fonctionnement normal
- [ ] [ ] Investiguer les 30-50% restants
- [ ] [ ] Ajuster matching pour edge cases

---

## **8. Commandes rapides**

```bash
# Voir tous les logs SBOM
grep '\[SBOM\]' ~/.medianet/logs/app.log | tail -50

# Compter matches vs non-matches
grep '\[SBOM\]' ~/.medianet/logs/app.log | \
  grep -c 'DIRECT\|TRANSITIVE' → matches
grep '\[SBOM\]' ~/.medianet/logs/app.log | \
  grep -c 'UNKNOWN' → no matches

# Export CVEs pour analysis externe
psql medianet_db -c "SELECT cve_id, package_name, component_name,
                            direct_or_transitive FROM cve_entries
                     WHERE scan_id = 52" > cves_scan_52.csv

# Vérifier temps d'enrichissement
grep 'Enrichment summary' ~/.medianet/logs/app.log | tail -5
```

---

## **Résumé des fixes appliqués**

| Fix                      | Status  | Impact                                         |
| ------------------------ | ------- | ---------------------------------------------- |
| Bug Trivy PURL ligne 332 | ✅ DONE | MEDIUM → Grype fonctionne, Trivy partiellement |
| Logging amélioré         | ✅ DONE | INFO → Diagnostiquer plus facilement           |
| Détection SBOM absent    | ✅ DONE | HIGH → Warning clair si SBOM absent            |

**Prochain:** Exécuter les tests pour valider, puis scanner pour vérifier les résultats réels.
