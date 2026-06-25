# 🔍 Diagnostic SBOM - Pourquoi les CVEs ne matchent pas

**Date:** 18 juin 2026  
**Scan ID:** 52  
**Problème:** Presque aucune CVE ne match avec le SBOM

---

## **📊 Sommaire exécutif**

```
✓ Grype détecte:     ~50 CVEs (avec purl généralement)
✓ Trivy détecte:     ~30 CVEs (purl = null à cause d'un BUG)
✗ SBOM match:        ~5 CVEs seulement

Taux de match: 5/80 = 6% ❌

Raison: 3 problèmes en cascade
```

---

## **1️⃣ Bug découvert : Trivy PURL extraction**

### **Ligne bugguée (ResultParserService.java:332)**

```java
// ❌ C'est du code mort illogique
String purl = text(v, "PkgIdentifier") != null ? null : null;
```

### **Analyse**

- La condition `text(v, "PkgIdentifier") != null ? null : null` revient à faire `null`
- Peu importe si le champ existe ou pas, purl sera toujours null
- **Impact:** Aucun CVE de Trivy n'a de PURL

### **Fix appliqué**

```java
// ✓ Correct maintenant
String purl = null;
JsonNode pkgId = v.get("PkgIdentifier");
if (pkgId != null) {
    purl = text(pkgId, "PURL");
}
```

---

## **2️⃣ Grype fonctionne bien**

```java
// ✓ Correct dans Grype (ligne 207)
String purl = artifact != null ? text(artifact, "purl") : null;
```

**Donc:**

- ✓ Grype extractions = OK (purl généralement présent)
- ❌ Trivy extractions = cassées (purl toujours null)

---

## **3️⃣ Chaîne de matching du SBOM**

Le matching utilise **3 niveaux de priorité** :

```
┌─ Niveau 1: PURL (plus précis)
│  purl: "pkg:maven/io.jsonwebtoken:jjwt-api@0.12.5"
│  ├─ Grype: ✓ Trouvé si présent dans artifact.purl
│  └─ Trivy: ✗ Null (BUG) → skip ce niveau
│
├─ Niveau 2: bomRef (identifiant unique)
│  bomRef: "artifact.id" ou null généralement
│  ├─ Grype: généralement null
│  └─ Trivy: généralement null
│
└─ Niveau 3: name+version+ecosystem (fallback)
   Key: "jjwt-api|0.12.5|maven"
   ├─ Match? Dépend si SBOM PRÉSENT
   └─ Si absence: UNKNOWN + LOW confidence
```

---

## **4️⃣ Pourquoi ton tableau montre "Aucun match"**

### **Exemple 1: jjwt-api (présent dans SBOM)**

```
CVE détectée:
  packageName: "jjwt-api"
  version: "0.12.5"
  ecosystem: "maven"
  purl: null (Trivy) ou "pkg:maven/..." (Grype)

Clé pour matching:
  Si TRIVY: "CVE-XXX|jjwt-api|0.12.5|maven|mf:Backend/pom.xml"
  Si GRYPE: "CVE-XXX|pkg:maven/io.jsonwebtoken:jjwt-api@0.12.5|mf:Backend"

SBOM (si présent):
  jjwt-api v0.12.5
    ├─ name: "jjwt-api"
    ├─ version: "0.12.5"
    └─ PURL: "pkg:maven/io.jsonwebtoken:jjwt-api@0.12.5"

Résultat Grype: ✓ MATCH par PURL → DIRECT (depth=1)
Résultat Trivy:  ✗ NO MATCH (purl=null) → UNKNOWN (depth=0)
```

### **Exemple 2: postgresql (version inconnue)**

```
CVE détectée:
  packageName: "postgresql"
  version: "UNKNOWN" ❌ ← Problème!
  ecosystem: "deb"

SBOM (si présent):
  postgresql v13.0
    ├─ version: "13.0"
    └─ ecosystem: "deb"

Matching par name+version+eco:
  Clé CVE: "postgresql|UNKNOWN|deb"
  Clé SBOM: "postgresql|13.0|deb"
  → Versions différentes: UNKNOWN vs 13.0
  → PAS DE MATCH ❌
```

### **Exemple 3: spring-boot-starter-web**

```
CVE détectée:
  packageName: "spring-boot-starter-web"
  version: "UNKNOWN" ❌ Grype/Trivy ne trouvent pas la version
  ecosystem: "maven"
  manifestFile: null (pas d'info sur le chemin)

SBOM (si présent):
  spring-boot-starter-web v3.1.4
    ├─ version: "3.1.4"
    ├─ moduleName: "Backend"
    └─ manifestFile: "Backend/pom.xml"

Matching échoue sur:
  ✗ Version: "UNKNOWN" != "3.1.4"
  ✗ Manifest: null != "Backend/pom.xml"

→ UNKNOWN + LOW confidence
```

---

## **5️⃣ Problèmes racine**

| #     | Problème                     | Source                         | Impact                     | Fix     |
| ----- | ---------------------------- | ------------------------------ | -------------------------- | ------- |
| **A** | PURL extraction null (Trivy) | BUG logique ligne 332          | Perte du meilleur matching | ✓ FIXED |
| **B** | Version = "UNKNOWN"          | Scanner ≠ pom.xml              | Matching niveau 3 échoue   | À faire |
| **C** | SBOM absent/vide             | Docker no sbom.json            | Tout reste UNKNOWN         | À faire |
| **D** | manifestFile null            | Grype/Trivy ne l'extraient pas | Module non dérivé          | À faire |

---

## **6️⃣ Actions correctives immédiates**

### **✓ FAIT (1/4)**

- ✅ Fix du bug Trivy PURL (ligne 332)

### **À faire (3/4)**

1. **Améliorer l'extraction de version** dans ResultParserService
   - Pour Grype: chercher dans `artifact` plus profondément
   - Pour Trivy: avoir Target + Type suffisent, mais version doit être `InstalledVersion`

2. **Ajouter logging de diagnostic** pour voir ce qui se passe réellement

   ```java
   log.info("[SBOM] Matching attempt: cveId={} purl={} name={} version={} eco={}",
           cveId, purl, pkg, version, ecosystem);
   log.info("[SBOM] Component found: {} → {}", comp != null ? comp.name : "NONE",
           result.directOrTransitive);
   ```

3. **Vérifier que SBOM est généré** par le scanner Docker
   - Scanner doit produire `sbom.cdx.json` ou `sbom.syft.json`
   - Check: `resultsDir/sbom.*.json` existe-t-il?

---

## **7️⃣ Logs de debug attendus (après fix)**

### **Si SBOM absent:**

```
[SBOM] No SBOM data available — all 80 CVEs get UNKNOWN/LOW confidence
[SBOM] Enrichment complete: 0/80 CVEs resolved (80+ UNKNOWN/LOW)
```

### **Si SBOM présent + bien formé:**

```
[SBOM] Parsing sbom.cdx.json (45678 bytes)
[SBOM] CycloneDX sbom.cdx.json parsed: 42 components, 38 dependency links
[SBOM] Enrichment complete: 35/80 CVEs resolved (45+ UNKNOWN/LOW)
```

### **Pour une CVE spécifique qui devrait matcher:**

```
[SBOM] CVE-2021-1234 → DIRECT (depth=1, confidence=HIGH)
       path=root → jjwt-api@0.12.5
```

---

## **8️⃣ Checklist diagnostic**

Avant d'aller plus loin, vérifiez:

- [ ] Bug Trivy PURL = fixé (ligne 332)
- [ ] Docker génère effectivement un SBOM?
  - Commande: `ls -la <resultsDir>/sbom*.json`
- [ ] SBOM contient les vrais composants Backend?
  - Vérifier: `jjwt-api`, `spring-boot-*`, etc.
- [ ] Versions dans SBOM vs Grype/Trivy matchent?
  - SBOM: `jjwt-api v0.12.5`
  - CVE: `packageVersion: 0.12.5` ou `null`?

---

## **Conclusion**

Le SBOM **ne marche pas correctement** car:

1. ✓ **BUG TRIVY** = FIXÉ (purl toujours null)
2. ⚠️ **Version missing** = à investiguer (UNKNOWN vs numéro réel)
3. ⚠️ **SBOM absent?** = à vérifier (Docker doit le générer)
4. ⚠️ **Mismatch names** = peut arriver (maven vs io.jsonwebtoken:...)

**Prochaine étape:** Lancer un scan et regarder les logs `[SBOM]` pour identifier précisément où ça échoue.
