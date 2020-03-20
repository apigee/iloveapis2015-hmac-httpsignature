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
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

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
