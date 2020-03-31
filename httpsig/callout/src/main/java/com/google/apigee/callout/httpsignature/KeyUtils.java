// Copyright 2018 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package com.google.apigee.callout.httpsignature;

import com.google.common.io.BaseEncoding;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

public final class KeyUtils {

    private KeyUtils() {}

    private static String reformIndents(String s) {
        return s.trim().replaceAll("([\\r|\\n] +)","\n");
    }

    public static PublicKey decodePublicKey(String publicKeyString) throws KeyParseException {
        try {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            publicKeyString = reformIndents(publicKeyString);
            PEMParser pemParser = new PEMParser(new StringReader(publicKeyString));
            Object object = pemParser.readObject();
            if (object == null) {
                throw new KeyParseException("unable to read anything when decoding public key");
            }
            return converter.getPublicKey((org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) object);
        }
        catch (KeyParseException exc0) {
            throw exc0;
        }
        catch (Exception exc1) {
            throw new KeyParseException("cannot instantiate public key", exc1);
        }
    }


    public static PublicKey certStringToPublicKey(String s)
        throws InvalidKeySpecException, CertificateException, UnsupportedEncodingException {
        s = s.trim();

        if (s.startsWith("-----BEGIN CERTIFICATE-----") &&
            s.endsWith("-----END CERTIFICATE-----")) {
            // This is an X509 cert;
            // Strip the prefix and suffix.
            s = s.substring(27, s.length() - 25);
        }
        // else, assume it is a bare base-64 encoded string

        s = s.replaceAll("[\\r|\\n| ]","");
        // base64-decode it, and  produce a public key from the result
        byte[] certBytes = BaseEncoding.base64().decode(s);
        ByteArrayInputStream is = new ByteArrayInputStream(certBytes);
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
        PublicKey key = cer.getPublicKey();
        return key;

    }

    public static PublicKey pemFileStringToPublicKey(String s)
        throws InvalidKeySpecException,
               CertificateException,
               UnsupportedEncodingException,
               NoSuchAlgorithmException,
               KeyParseException {

        PublicKey key = decodePublicKey(s);
        if (key==null) {
            key = certStringToPublicKey(s);
        }
        return key; // maybe null
    }

    private static String unUrlSafe(String s) {
        s = s.replaceAll("-","+")
            .replaceAll("_","/");
        return s;
    }

    public static PublicKey pubKeyFromModulusAndExponent(String modulus_b64, String exponent_b64)
        throws NoSuchAlgorithmException,
               InvalidKeySpecException    {

        modulus_b64 = KeyUtils.unUrlSafe(modulus_b64)
            .replaceAll("[\\r|\\n| ]","");
        exponent_b64 = KeyUtils.unUrlSafe(exponent_b64)
            .replaceAll("[\\r|\\n| ]","");

        byte[] decodedModulus = BaseEncoding.base16().decode( modulus_b64 );
        byte[] decodedExponent = BaseEncoding.base16().decode( exponent_b64 );

        String modulus_hex = BaseEncoding.base16().encode( decodedModulus );
        String exponent_hex = BaseEncoding.base16().encode( decodedExponent );

        BigInteger modulus = new BigInteger(modulus_hex, 16);
        BigInteger publicExponent = new BigInteger(exponent_hex, 16);

        PublicKey publicKey = KeyFactory
            .getInstance("RSA")
            .generatePublic(new RSAPublicKeySpec(modulus, publicExponent));

        return publicKey;
    }

    // public static String publicKeyPem(PublicKey rsaKey) {
    //     byte[] data = rsaKey.getEncoded();
    //     String base64encoded = Base64.encodeBase64String(data);
    //     Pattern p = Pattern.compile(".{1,64}");
    //     Matcher m = p.matcher(base64encoded);
    //     String pem = "-----BEGIN PUBLIC KEY-----\n" +
    //         m.replaceAll("$0\n") +
    //         "-----END PUBLIC KEY-----\n";
    //     return pem;
    // }

    public static PrivateKey decodePrivateKey(String privateKeyString, String password) throws KeyParseException {

        try {
            return readKey(privateKeyString, password);
        }
        catch (Exception exc1) {
            throw new KeyParseException("cannot instantiate private key", exc1);
        }
    }

  private static RSAPrivateKey readKey(String privateKeyPemString, String password)
      throws IOException, OperatorCreationException, PKCSException, InvalidKeySpecException,
          NoSuchAlgorithmException {
    if (privateKeyPemString == null) {
      throw new IllegalStateException("PEM String is null");
    }
    if (password == null) password = "";

    PEMParser pr = null;
    try {
      pr = new PEMParser(new StringReader(privateKeyPemString));
      Object o = pr.readObject();

      if (o == null) {
        throw new IllegalStateException("Parsed object is null.  Bad input.");
      }
      if (!((o instanceof PEMEncryptedKeyPair)
          || (o instanceof PKCS8EncryptedPrivateKeyInfo)
          || (o instanceof PrivateKeyInfo)
          || (o instanceof PEMKeyPair))) {
        // System.out.printf("found %s\n", o.getClass().getName());
        throw new IllegalStateException(
            "Didn't find OpenSSL key. Found: " + o.getClass().getName());
      }

      JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

      if (o instanceof PEMKeyPair) {
        // eg, "openssl genrsa -out keypair-rsa-2048-unencrypted.pem 2048"
        return (RSAPrivateKey) converter.getPrivateKey(((PEMKeyPair) o).getPrivateKeyInfo());
      }

      if (o instanceof PrivateKeyInfo) {
        // eg, "openssl genpkey  -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out keypair.pem"
        return (RSAPrivateKey) converter.getPrivateKey((PrivateKeyInfo) o);
      }

      if (o instanceof PKCS8EncryptedPrivateKeyInfo) {
        // eg, "openssl genpkey -algorithm rsa -aes-128-cbc -pkeyopt rsa_keygen_bits:2048 -out
        // private-encrypted.pem"
        PKCS8EncryptedPrivateKeyInfo pkcs8EncryptedPrivateKeyInfo =
            (PKCS8EncryptedPrivateKeyInfo) o;
        JceOpenSSLPKCS8DecryptorProviderBuilder decryptorProviderBuilder =
            new JceOpenSSLPKCS8DecryptorProviderBuilder();
        InputDecryptorProvider decryptorProvider =
            decryptorProviderBuilder.build(password.toCharArray());
        PrivateKeyInfo privateKeyInfo =
            pkcs8EncryptedPrivateKeyInfo.decryptPrivateKeyInfo(decryptorProvider);
        return (RSAPrivateKey) converter.getPrivateKey(privateKeyInfo);
      }

      if (o instanceof PEMEncryptedKeyPair) {
        // eg, "openssl genrsa -aes256 -out private-encrypted-aes-256-cbc.pem 2048"
        PEMDecryptorProvider decProv =
            new JcePEMDecryptorProviderBuilder().setProvider("BC").build(password.toCharArray());
        KeyPair keyPair = converter.getKeyPair(((PEMEncryptedKeyPair) o).decryptKeyPair(decProv));
        return (RSAPrivateKey) keyPair.getPrivate();
      }
    } finally {
      if (pr != null) {
        pr.close();
      }
    }
    throw new IllegalStateException("unknown PEM object");
  }


    public static class KeyParseException extends Exception {

        private static final long serialVersionUID = 0L;

        KeyParseException(String message) {
            super(message);
        }

        KeyParseException(String message, Throwable th) {
            super(message, th);
        }
    }

}
