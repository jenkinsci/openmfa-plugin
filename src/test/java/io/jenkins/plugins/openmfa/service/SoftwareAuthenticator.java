package io.jenkins.plugins.openmfa.service;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import net.sf.json.JSONObject;

/**
 * Minimal ES256 software authenticator producing genuine clientDataJSON,
 * authenticatorData, a hand-encoded CBOR {@code none} attestationObject and
 * real P-256 signatures. Always UP+UV, all-zero AAGUID, not thread-safe.
 */
final class SoftwareAuthenticator {

  /** User present, user verified. */
  private static final byte FLAG_ASSERTION = 0x05;

  /** User present, user verified, attested credential data included. */
  private static final byte FLAG_REGISTRATION = 0x45;

  private static final SecureRandom RANDOM = new SecureRandom();

  private static String b64(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  /** CBOR byte-string header plus payload. */
  private static byte[] cborBytes(byte[] value) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    if (value.length <= 23) {
      out.write(0x40 | value.length);
    } else if (value.length <= 255) {
      out.write(0x58);
      out.write(value.length);
    } else {
      out.write(0x59);
      out.write((value.length >> 8) & 0xFF);
      out.write(value.length & 0xFF);
    }
    out.writeBytes(value);
    return out.toByteArray();
  }

  /** CBOR text-string header plus UTF-8 payload (short strings only). */
  private static byte[] cborText(String value) {
    byte[] raw = value.getBytes(StandardCharsets.UTF_8);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(0x60 | raw.length);
    out.writeBytes(raw);
    return out.toByteArray();
  }

  private static byte[] concat(byte[]... parts) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (byte[] part : parts) {
      out.writeBytes(part);
    }
    return out.toByteArray();
  }

  /** Big-endian 32-bit encoding, as used for the signature counter. */
  private static byte[] int32(long value) {
    return new byte[] {
      (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8),
      (byte) value
    };
  }

  /** Left-pads an unsigned coordinate to the P-256 field size. */
  private static byte[] pad32(BigInteger value) {
    byte[] raw = value.toByteArray();
    byte[] padded = new byte[32];
    if (raw.length > 32) {
      System.arraycopy(raw, raw.length - 32, padded, 0, 32);
    } else {
      System.arraycopy(raw, 0, padded, 32 - raw.length, raw.length);
    }
    return padded;
  }

  private static byte[] sha256(byte[] input) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(input);
  }

  private final byte[] credentialId = new byte[32];

  private final KeyPair keyPair;

  SoftwareAuthenticator() throws Exception {
    RANDOM.nextBytes(credentialId);
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    keyPair = generator.generateKeyPair();
  }

  /**
   * Builds a {@code navigator.credentials.get()} response for
   * {@code startAssertion} JSON.
   */
  String authenticate(String requestJson, String origin, long signatureCount)
    throws Exception {
    JSONObject publicKey =
      JSONObject.fromObject(requestJson).getJSONObject("publicKey");
    String challenge = publicKey.getString("challenge");
    String rpId = publicKey.getString("rpId");

    byte[] clientDataJson =
      clientData("webauthn.get", challenge, origin)
        .getBytes(StandardCharsets.UTF_8);
    byte[] authenticatorData =
      concat(
        sha256(rpId.getBytes(StandardCharsets.UTF_8)),
        new byte[] {FLAG_ASSERTION},
        int32(signatureCount)
      );

    Signature signer = Signature.getInstance("SHA256withECDSA");
    signer.initSign(keyPair.getPrivate());
    signer.update(concat(authenticatorData, sha256(clientDataJson)));
    byte[] signature = signer.sign();

    return "{\"type\":\"public-key\",\"id\":\""
      + credentialIdBase64Url()
      + "\",\"rawId\":\"" + credentialIdBase64Url()
      + "\",\"response\":{\"authenticatorData\":\"" + b64(authenticatorData)
      + "\",\"clientDataJSON\":\"" + b64(clientDataJson)
      + "\",\"signature\":\"" + b64(signature)
      + "\"},\"clientExtensionResults\":{}}";
  }

  /** The credential id this authenticator reports, base64url encoded. */
  String credentialIdBase64Url() {
    return b64(credentialId);
  }

  /**
   * Builds a {@code navigator.credentials.create()} response for
   * {@code startRegistration} JSON.
   */
  String register(String optionsJson, String origin) throws Exception {
    JSONObject publicKey =
      JSONObject.fromObject(optionsJson).getJSONObject("publicKey");
    String challenge = publicKey.getString("challenge");
    String rpId = publicKey.getJSONObject("rp").getString("id");

    byte[] clientDataJson =
      clientData("webauthn.create", challenge, origin)
        .getBytes(StandardCharsets.UTF_8);
    byte[] authenticatorData =
      concat(
        sha256(rpId.getBytes(StandardCharsets.UTF_8)),
        new byte[] {FLAG_REGISTRATION},
        int32(0),
        new byte[16], // AAGUID
        new byte[] {
          (byte) (credentialId.length >> 8), (byte) credentialId.length
        },
        credentialId,
        coseKey()
      );

    byte[] attestationObject =
      concat(
        new byte[] {(byte) 0xA3},
        cborText("fmt"),
        cborText("none"),
        cborText("attStmt"),
        new byte[] {(byte) 0xA0},
        cborText("authData"),
        cborBytes(authenticatorData)
      );

    return "{\"type\":\"public-key\",\"id\":\""
      + credentialIdBase64Url()
      + "\",\"rawId\":\"" + credentialIdBase64Url()
      + "\",\"response\":{\"attestationObject\":\"" + b64(attestationObject)
      + "\",\"clientDataJSON\":\"" + b64(clientDataJson)
      + "\"},\"clientExtensionResults\":{}}";
  }

  private String clientData(String type, String challenge, String origin) {
    return "{\"type\":\""
      + type + "\",\"challenge\":\"" + challenge
      + "\",\"origin\":\"" + origin + "\",\"crossOrigin\":false}";
  }

  /**
   * The COSE_Key for this key pair: a 5-entry CBOR map of
   * {@code kty=EC2, alg=ES256, crv=P-256, x, y}.
   */
  private byte[] coseKey() {
    ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
    return concat(
      new byte[] {(byte) 0xA5},
      new byte[] {0x01, 0x02}, // 1 (kty): 2 (EC2)
      new byte[] {0x03, 0x26}, // 3 (alg): -7 (ES256)
      new byte[] {0x20, 0x01}, // -1 (crv): 1 (P-256)
      new byte[] {0x21}, // -2 (x)
      cborBytes(pad32(publicKey.getW().getAffineX())),
      new byte[] {0x22}, // -3 (y)
      cborBytes(pad32(publicKey.getW().getAffineY()))
    );
  }
}
