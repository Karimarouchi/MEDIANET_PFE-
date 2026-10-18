package com.medianet.service;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Checks the HTTP message signature (RFC 9421, ed25519) Woodpecker puts on every extension call:
 * {@code Signature-Input: woodpecker-ci-extensions=("@request-target" "content-digest");created=…;alg="ed25519"}.
 * Only that exact component list is accepted, so a signature over less than the target and the body digest fails.
 */
final class WoodpeckerSignatureVerifier {

    static final String LABEL = "woodpecker-ci-extensions";
    private static final String COMPONENTS = "(\"@request-target\" \"content-digest\")";
    private static final Pattern INPUT = Pattern.compile(
            Pattern.quote(LABEL) + "=(" + Pattern.quote(COMPONENTS) + ";created=(\\d+);alg=\"ed25519\")$");
    private static final Pattern SIG = Pattern.compile(Pattern.quote(LABEL) + "=:([A-Za-z0-9+/=]+):$");
    private static final Pattern DIGEST = Pattern.compile("^sha-256=:([A-Za-z0-9+/=]+):$");
    /** A signed request older (or newer) than this is refused: limits replay of a captured call. */
    static final Duration MAX_SKEW = Duration.ofMinutes(5);

    private WoodpeckerSignatureVerifier() {
    }

    /** Null when the request is genuine, otherwise the reason it is refused (never echoes secrets). */
    static String verify(PublicKey key, String requestTarget, byte[] body, String contentDigest,
            String signatureInput, String signature, Instant now) {
        if (key == null) return "clé publique Woodpecker indisponible";
        if (requestTarget == null || contentDigest == null || signatureInput == null || signature == null) {
            return "en-têtes de signature absents";
        }
        Matcher in = INPUT.matcher(signatureInput.trim());
        if (!in.matches()) return "Signature-Input inattendu";
        Matcher sig = SIG.matcher(signature.trim());
        Matcher dig = DIGEST.matcher(contentDigest.trim());
        if (!sig.matches() || !dig.matches()) return "format de signature inattendu";

        long created = Long.parseLong(in.group(2));
        if (Math.abs(now.getEpochSecond() - created) > MAX_SKEW.toSeconds()) return "signature expirée";

        try {
            byte[] expected = MessageDigest.getInstance("SHA-256").digest(body == null ? new byte[0] : body);
            if (!MessageDigest.isEqual(expected, Base64.getDecoder().decode(dig.group(1)))) {
                return "le contenu ne correspond pas à son empreinte";
            }
            String base = "\"@request-target\": " + requestTarget + "\n"
                    + "\"content-digest\": " + contentDigest.trim() + "\n"
                    + "\"@signature-params\": " + in.group(1);
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(key);
            verifier.update(base.getBytes(StandardCharsets.UTF_8));
            return verifier.verify(Base64.getDecoder().decode(sig.group(1))) ? null : "signature invalide";
        } catch (Exception e) {
            return "signature illisible";
        }
    }

    /** PEM "PUBLIC KEY" (SPKI) as served by GET /api/signature/public-key. */
    static PublicKey parsePem(String pem) throws Exception {
        String b64 = pem.replaceAll("-----(BEGIN|END) PUBLIC KEY-----", "").replaceAll("\\s", "");
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(b64)));
    }
}
