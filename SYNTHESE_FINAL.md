# ✅ Synthèse - État de l'implémentation SBOM

**Date:** 18 juin 2026  
**Statut:** Partiellement opérationnel avec corrections appliquées

---

## **🎯 Objectif original**

Implémenter l'enrichissement SBOM pour les CVE détectées:

- ✅ 9 tâches de développement: COMPLÈTEMENT IMPLÉMENTÉES (zéro erreurs)
- ❌ Validation en production: 6% de success rate → **PAS ACCEPTABLE**

---

## **🔧 Travail effectué aujourd'hui (Session 2)**

### **1️⃣ Bug critique découvert et fixé**

**Fichier:** `ResultParserService.java` ligne 332  
**Problème:** Trivy PURL = null TOUJOURS (logique absurde)

```java
// ❌ AVANT (illogique)
String purl = text(v, "PkgIdentifier") != null ? null : null;

// ✅ APRÈS (correct)
String purl = null;
JsonNode pkgId = v.get("PkgIdentifier");
if (pkgId != null) {
    purl = text(pkgId, "PURL");
}
```

**Impact:**

- Trivy: ~30 CVEs affectées (purl toujours null)
- Grype: Non affecté (extraction correcte)
- Amélioration attendue: Success rate +20-30%

---

### **2️⃣ Logging diagnostic amélioré**

**Fichier:** `SbomEnrichmentService.java`

Ajouté logs pour identifier:

- Si SBOM est présent/absent
- Si composants trouvés ou non
- Success rate global
- Raison de l'absence de match (purl null, name mismatch, etc.)

```
[SBOM] ✓ SBOM parsed successfully with 42 components
[SBOM] ✓ CVE-2021-1234 → DIRECT (confidence=HIGH)
[SBOM] ✗ CVE-2021-5678 → UNKNOWN (no component match)
[SBOM] Enrichment summary: 35/80 resolved | 45 UNKNOWN | 0 errors
[SBOM] Success rate: 43%
```

---

### **3️⃣ Documentation complète créée**

| Document                      | Contenu                                | Utilité                        |
| ----------------------------- | -------------------------------------- | ------------------------------ |
| `DIAGNOSTIC_SBOM_SCAN52.md`   | Analyse du scan 52, 3 problèmes racine | Comprendre l'échec             |
| `DEBUG_GUIDE_SBOM.md`         | Procédure de débogage 8 étapes         | Diagnostiquer futurs problèmes |
| `SBOM_MECHANISM_EXPLAINED.md` | Explication architecture + cas d'échec | Comprendre le fonctionnement   |
| `SYNTHESE.md` (ce fichier)    | État global du projet                  | Faire le point                 |

---

## **📊 État actuel du code**

### **Backend**

| Fichier                       | Modification                  | Statut                  |
| ----------------------------- | ----------------------------- | ----------------------- |
| `CveEntry.java`               | +14 champs (nullable)         | ✅ FAIT S1              |
| `CveDto.java`                 | +14 propriétés                | ✅ FAIT S1              |
| `SbomParserService.java`      | Parse SBOM files              | ✅ FAIT S1              |
| `DependencyGraphService.java` | Résout DIRECT/TRANSITIVE      | ✅ FAIT S1              |
| `SbomEnrichmentService.java`  | Orchestre enrichissement      | ✅ FAIT S1 + logs S2    |
| `ResultParserService.java`    | Parsing Grype/Trivy + dédup   | ✅ FAIT S1 + BUG FIX S2 |
| `ScanService.java`            | Appelle SbomEnrichmentService | ✅ FAIT S1              |

### **Frontend**

| Fichier               | Modification                   | Statut     |
| --------------------- | ------------------------------ | ---------- |
| `Vulnerabilities.tsx` | Section "Composant vulnérable" | ✅ FAIT S1 |
| `api.ts`              | CveDto interface +14 champs    | ✅ FAIT S1 |

### **Tests**

| Fichier                      | Couverture | Statut     |
| ---------------------------- | ---------- | ---------- |
| `SbomParserServiceTest.java` | 7 tests    | ✅ CRÉÉ S1 |

### **Compilation**

✅ Zéro erreurs  
✅ Zéro warnings

---

## **🔍 Problèmes identifiés et solutions**

### **Problème 1: Version = UNKNOWN**

**Symptôme:**

```
CVE de Grype: spring-boot-starter-web v"UNKNOWN"
SBOM: spring-boot-starter-web v"3.1.4"
→ name+version matching échoue (UNKNOWN ≠ 3.1.4)
```

**Cause:**

- Grype/Trivy ne trouvent pas les versions héritées (Maven override)
- Il n'existe pas de lockfile avec versions explicites

**Solution:**

- Générer SBOM avec Maven: `mvn cyclonedx:makeBom` (donne vraies versions)
- Ou: Importer versions depuis `target/dependency-report.json`
- Complexité: MEDIUM

---

### **Problème 2: PURL null dans Trivy**

**Symptôme:**

```
Trivy: purl = null pour tous les CVEs
Grype: purl = "pkg:maven/..." généralement présent
```

**Cause:**
🐛 Bug logique à ligne 332 du ResultParserService.java

**Solution:**
✅ FIXÉ S2 - Logique corrigée

---

### **Problème 3: Noms ne matchent pas**

**Symptôme:**

```
Grype: "jjwt-api"
SBOM: "io.jsonwebtoken:jjwt-api"
→ Pas de match par nom
```

**Cause:**

- Maven groupId:artifactId vs artifact name seul
- SBOM peut avoir noms complets ou simplifiés

**Solution:**

- Normaliser: extraire artifactId du PURL
- Ou: Améliorer l'extraction PURL pour tous les outils
- Complexité: MEDIUM

---

### **Problème 4: SBOM absent**

**Symptôme:**

```
resultsDir/scan-52/ ne contient pas sbom*.json
→ All CVEs get UNKNOWN/LOW confidence
```

**Cause:**

- Docker scanner n'a pas généré de SBOM
- Ou: SBOM généré mais avec mauvaise extension

**Solution:**

- S'assurer que scanner inclut étape de génération SBOM
- Utiliser `cdxgen`, `syft`, ou `cyclonedx-maven-plugin`
- Complexité: LOW (config Docker uniquement)

---

## **📈 Amélioration attendue par fix**

```
Avant tous les fixes:
  Success rate = 6% (5/80 CVEs)

Après BUG FIX Trivy PURL:
  Success rate = ~35% (28/80 CVEs)  ← +20-30%
  Raison: Trivy PURL maintenant extraits

Après FIX Version UNKNOWN:
  Success rate = ~55% (44/80 CVEs)  ← +20%
  Raison: Fallback name+version matching marche mieux

Après FIX SBOM generation:
  Success rate = ~70%+ (56+/80 CVEs)
  Raison: Données plus complètes et fiables

Après FIX Name normalization:
  Success rate = ~85% (68/80 CVEs)
  Raison: Plus d'edge cases couverts
```

---

## **✅ Checklist d'implémentation**

### **Phase 1: Architecture (S1 - COMPLÈTEMENT FAIT)**

- [x] CveEntry avec 14 champs
- [x] CveDto avec 14 propriétés
- [x] SbomParserService (700+ lignes)
- [x] DependencyGraphService (450+ lignes)
- [x] SbomEnrichmentService (300+ lignes)
- [x] Injection dans ScanService
- [x] Frontend display "Composant vulnérable"
- [x] Tests unitaires (7 tests)
- [x] Compilation: 0 erreurs

### **Phase 2: Correctifs (S2 - EN COURS)**

- [x] BUG FIX: Trivy PURL ligne 332
- [x] Logging amélioré pour diagnostic
- [ ] **TODO:** Versions UNKNOWN → vraies versions (Maven)
- [ ] **TODO:** Normalisation noms (groupId:artifactId)
- [ ] **TODO:** Vérifier SBOM génération Docker
- [ ] **TODO:** Tester sur scan réel

### **Phase 3: Validation (À FAIRE)**

- [ ] Lancer scan local
- [ ] Vérifier logs [SBOM]
- [ ] Calculer success rate réel
- [ ] Si < 50%, investiguer D1/2/3 problèmes
- [ ] Appliquer solutions manquantes

---

## **🚀 Next Steps (Priorité ordre)**

### **🔴 URGENT (bloquer success rate bas)**

1. **Lancer un scan et observer les logs**

   ```bash
   # Backend logs avec [SBOM]
   # Chercher: "Success rate:"
   # Si < 50% → continuer diagnostic
   ```

2. **Vérifier si SBOM est généré**

   ```bash
   ls -la scan-results/*/sbom*
   # Si absent → ajouter génération dans Docker
   ```

3. **Vérifier les versions**
   ```bash
   # Si UNKNOWN nombreux → importer depuis Maven
   # Solution: utiliser target/dependency-report.json
   ```

### **🟡 IMPORTANT (améliorer to 60%+)**

4. **Normaliser noms Maven**

   ```
   Grype: "jjwt-api"
   SBOM: "io.jsonwebtoken:jjwt-api"
   → Extraire artifactId depuis PURL en fallback
   ```

5. **Améliorer extraction version**
   ```
   Pour Maven: Chercher version dans pom.xml via Maven plugin
   Pour npm: Chercher dans package-lock.json
   ```

### **🟢 NICE-TO-HAVE (atteindre 85%+)**

6. **Supporteur multiples formats SBOM**

   ```
   Actuellement: CycloneDX ✓ Syft ✓
   Ajouter: SPDX, autres formats
   ```

7. **Enrichir path avec versions**
   ```
   Actuellement: "root → dep1 → dep2"
   Améliorer: "root@v1 → dep1@v2 → dep2@v3"
   ```

---

## **💡 Recommendations**

### **Pour tester maintenant**

1. **Lancer un scan local**

   ```bash
   Backend: ./mvnw.cmd spring-boot:run
   Frontend: npm start
   UI: New scan → Local Repository
   ```

2. **Regarder les logs backend**

   ```
   Chercher: "[SBOM]" messages
   Chercher: "Success rate: X%"
   ```

3. **Documenter les résultats**
   ```
   Note: success rate, composants matchés, failure reasons
   ```

### **Si success rate < 30%**

1. Appliquer fix des 3 problèmes prioritaires (Versions, Names, SBOM absent)
2. Re-tester
3. Calculer improvement

### **Si success rate 30-60%**

1. Appliquer fix problèmes MEDIUM (normalisation noms)
2. Considérer edge cases identifiés
3. Potentiellement nécessaire refactor du matching logic

### **Si success rate > 60%**

🎉 SBOM fonctionne acceptablement

- Investiguer reste des 30-40% pour edge cases
- Documenter limitations identifiées
- Considérer optional improvements (step 6-7)

---

## **📝 Synthèse exécutive**

**État:** 95% implementé, 20% en production  
**Problème:** Success rate 6% (inacceptable)  
**Cause:** 4 issues identifiées (1 bug + 3 data quality)  
**Fixes appliqués:** BUG FIX + logging  
**Amélioration attendue:** 6% → 35%+ après BUG FIX  
**Prochaine action:** Lancer scan pour valider + appliquer fixes manquants

---

## **Documents de référence**

1. [DIAGNOSTIC_SBOM_SCAN52.md](./DIAGNOSTIC_SBOM_SCAN52.md) - Analyse détaillée scan 52
2. [DEBUG_GUIDE_SBOM.md](./DEBUG_GUIDE_SBOM.md) - Guide de débogage étape par étape
3. [SBOM_MECHANISM_EXPLAINED.md](./SBOM_MECHANISM_EXPLAINED.md) - Architecture et mécanisme complet
4. Code source: `Backend/src/main/java/com/medianet/service/Sbom*.java`

---

**Auteur:** GitHub Copilot  
**Dernière mise à jour:** 18 juin 2026
