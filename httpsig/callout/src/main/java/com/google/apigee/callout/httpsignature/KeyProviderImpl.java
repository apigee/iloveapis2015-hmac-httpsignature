package com.google.apigee.callout.httpsignature;

import com.apigee.flow.message.MessageContext;
import com.google.apigee.callout.httpsignature.KeyUtils.KeyParseException;
import com.google.common.io.BaseEncoding;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.Optional;

class KeyProviderImpl implements KeyProvider {
  MessageContext c;
  Map properties;

  public KeyProviderImpl(MessageContext msgCtxt, Map properties) {
    this.c = msgCtxt;
    this.properties = properties;
  }

  public byte[] getSecretKey() throws IllegalStateException {
    String encodedKey = (String) properties.get("secret-key");
    if (encodedKey == null || encodedKey.equals("")) {
      throw new IllegalStateException(
          "configuration error: secret-key is not specified or is empty.");
    }
    encodedKey = PackageUtils.resolvePropertyValue(encodedKey, c);
    if (encodedKey == null || encodedKey.equals("")) {
      throw new IllegalStateException("configuration error: secret-key is null or empty.");
    }

    String keyEncoding = (String) properties.get("secret-key-encoding");
    if (keyEncoding == null || keyEncoding.equals("")) {
      return encodedKey.getBytes(StandardCharsets.UTF_8);
    }
    keyEncoding = PackageUtils.resolvePropertyValue(keyEncoding, c);
    if (keyEncoding == null || keyEncoding.equals("")) {
      return encodedKey.getBytes(StandardCharsets.UTF_8);
    }

    final Optional<SecretKeyEncoding> parsedEncoding =
        SecretKeyEncoding.getValueOf(keyEncoding.toUpperCase());

    if (parsedEncoding.isPresent()) {
      switch (parsedEncoding.get()) {
        case HEX:
        case BASE16:
          return BaseEncoding.base16()
              .lowerCase()
              .decode(encodedKey.replaceAll("\\s", "").toLowerCase());
        case BASE64:
          return BaseEncoding.base64().decode(encodedKey);
        case BASE64URL:
          return BaseEncoding.base64Url().decode(encodedKey);
      }
    }
    return encodedKey.getBytes(StandardCharsets.UTF_8);
  }

  public PublicKey getPublicKey()
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException,
          KeyParseException {
    String publicKeyString = (String) properties.get("public-key");

    // There are various ways to specify the public key.

    String pemfile = (String) properties.get("pemfile");
    if (pemfile != null && !pemfile.equals("")) {
      throw new IllegalStateException("pemfile is no longer supported.");
    }

    // Try "public-key"
    if (publicKeyString != null) {
      if (publicKeyString.equals("")) {
        throw new IllegalStateException("public-key must be non-empty");
      }
      publicKeyString = PackageUtils.resolvePropertyValue(publicKeyString, c);

      if (publicKeyString == null || publicKeyString.equals("")) {
        throw new IllegalStateException(
            "public-key variable resolves to empty; invalid when algorithm is RS*");
      }
      try {
        return KeyUtils.decodePublicKey(publicKeyString);
      } catch (KeyParseException ex) {
        throw new InvalidKeySpecException("must be PKCS#1 or PKCS#8");
      }
    }

    // // Try "modulus" + "exponent"
    // String modulus = (String) this.properties.get("modulus");
    // String exponent = (String) this.properties.get("exponent");
    //
    // if ((modulus != null) && (exponent != null)) {
    //     modulus = resolvePropertyValue(modulus, msgCtxt);
    //     exponent = resolvePropertyValue(exponent, msgCtxt);
    //
    //     if (modulus==null || modulus.equals("") ||
    //         exponent==null || exponent.equals("")) {
    //         throw new IllegalStateException("modulus or exponent resolves to empty; invalid when
    // algorithm is RS*");
    //     }
    //
    //     PublicKey key = KeyUtils.pubKeyFromModulusAndExponent(modulus, exponent);
    //     return key;
    // }

    // Try certificate
    String certString = (String) properties.get("certificate");
    if (certString != null) {
      if (certString.equals("")) {
        throw new IllegalStateException("certificate must be non-empty");
      }
      certString = PackageUtils.resolvePropertyValue(certString, c);
      // msgCtxt.setVariable("jwt_certstring", certString);
      if (certString == null || certString.equals("")) {
        throw new IllegalStateException(
            "certificate variable resolves to empty; invalid when algorithm is RS*");
      }
      PublicKey key = KeyUtils.certStringToPublicKey(certString);
      if (key == null) {
        throw new InvalidKeySpecException("invalid certificate format");
      }
      return key;
    }

    throw new IllegalStateException("no source for public-key");

    // // last chance
    // String pemfile = (String) properties.get("pemfile");
    // if (pemfile == null || pemfile.equals("")) {
    //   throw new IllegalStateException("must specify pemfile or public-key or certificate when
    // algorithm is RS*");
    // }
    // pemfile = PackageUtils.resolvePropertyValue(pemfile, c);
    // //msgCtxt.setVariable("jwt_pemfile", pemfile);
    // if (pemfile == null || pemfile.equals("")) {
    //   throw new IllegalStateException("pemfile resolves to nothing; invalid when algorithm is
    // RS*");
    // }
    //
    // InputStream in = getResourceAsStream(pemfile);
    // byte[] keyBytes = new byte[in.available()];
    // in.read(keyBytes);
    // in.close();
    // publicKeyString = new String(keyBytes, "UTF-8");
    //
    // // allow pemfile resolution as Certificate or Public Key
    // PublicKey key = KeyUtils.pemFileStringToPublicKey(publicKeyString);
    // if (key==null) {
    //   throw new InvalidKeySpecException("invalid pemfile format");
    // }
    // return key;
  }
}
