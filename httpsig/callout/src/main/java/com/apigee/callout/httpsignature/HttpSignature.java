// HttpSignature.java
// ------------------------------------------------------------------
//
// Author: Dino
// Created Fri Aug 14 14:42:41 2015
//
// Last saved: <2015-October-20 16:19:38>
// ------------------------------------------------------------------
//
// Copyright (c) 2015 Dino Chiesa
// All rights reserved.
//
// ------------------------------------------------------------------

package com.apigee.callout.httpsignature;

import java.util.Map;
import java.util.HashMap;
import java.util.Collections;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.net.URISyntaxException;

import java.nio.charset.StandardCharsets;

import java.security.PublicKey;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.Signature;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;

public class HttpSignature {

    // public static final Map<String, String> supportedRsaAlgorithms;
    // static {
    //     Map<String, String> a = new HashMap<String, String>();
    //     a.put("rsa-sha1", "SHA1withRSA");
    //     a.put("rsa-sha256", "SHA256withRSA");
    //     a.put("rsa-sha512", "SHA512withRSA");
    //     supportedRsaAlgorithms = Collections.unmodifiableMap(a);
    // }

    public static final Map<String, String> supportedAlgorithms;
    static {
        Map<String, String> a = new HashMap<String, String>();
        a.put("rsa-sha1", "SHA1withRSA");
        a.put("rsa-sha256", "SHA256withRSA");
        a.put("rsa-sha512", "SHA512withRSA");
        a.put("hmac-sha1", "HmacSHA1");
        a.put("hmac-sha256", "HmacSHA256");
        a.put("hmac-sha512", "HmacSHA512");
        supportedAlgorithms = Collections.unmodifiableMap(a);
    }

    public static final String[] knownSignatureItems = {
        "keyId", "algorithm", "headers", "signature"
    };

    public String getKeyId() { return (String) props.get("keyId"); }
    public void setKeyId(String value) { props.put("keyId", value); }

    public String getAlgorithm() { return (String) props.get("algorithm"); }
    public void setAlgorithm(String value) { props.put("algorithm", value); }

    public String[] getHeaders() {
        if (!props.containsKey("headers")) { return null; }
        return (String[]) props.get("headers");
    }
    public void setHeaders(String[] value) { props.put("headers", value); }

    public String getSignatureString() { return (String) props.get("signature"); }
    public byte[] getSignatureBytes() {
        return Base64.decodeBase64((String) props.get("signature"));
    }
    public void setSignatureString(String value) { props.put("signature", value); }

    private Map<String, Object> props = new HashMap<String, Object>();


    private boolean _isRsa = false;
    public boolean isRsa() {
        return _isRsa;
    }
    public boolean isHmac() {
        return !_isRsa;
    }

    public SigVerificationResult verify(String algorithm,
                                  ReadOnlyHttpSigHeaderMap hmap,
                                  KeyProvider kp)
        throws Exception {

        SigVerificationResult result = new SigVerificationResult();
        result.signingBase = this.getSigningBase(hmap);
        result.isValid = false;

        String javaAlgoName = HttpSignature.supportedAlgorithms.get(algorithm);
        if (this.isRsa()) {
            // RSA
            PublicKey publicKey = kp.getPublicKey();
            Signature sig = Signature.getInstance(javaAlgoName);
            sig.initVerify(publicKey);
            sig.update(result.signingBase.getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes = this.getSignatureBytes();
            result.isValid = sig.verify(signatureBytes);
        }
        else {
            // HMAC
            String signingKey = kp.getSecretKey();
            SecretKeySpec key = new SecretKeySpec(signingKey.getBytes("UTF-8"), javaAlgoName);
            Mac hmac = Mac.getInstance(javaAlgoName);
            hmac.init(key);

            result.computedSignature
                = Base64.encodeBase64String(hmac.doFinal(result.signingBase.getBytes("UTF-8")));

            String providedSignature = this.getSignatureString();
            result.isValid = result.computedSignature.equals(providedSignature);
        }
        return result;
    }

    public String getSigningBase(ReadOnlyHttpSigHeaderMap map) {
        String[] headers = this.getHeaders();
        String sigBase = "";
        String path, v;

        if (headers == null) {
            headers = new String[] { "date" };
        }

        for (int i=0; i < headers.length; i++) {
            if (!sigBase.equals("")) { sigBase += "\n";}
            String h = headers[i];
            v = map.getHeaderValue(h); // including special value
            if (v==null || v.equals("")) v = "unknown header " + h;
            sigBase += h + ": " + v;
        }
        return sigBase;
    }


    private void parseHttpSignatureHeader(String header)
        throws IllegalStateException, UnsupportedOperationException {
        Pattern re2 = Pattern.compile("([a-zA-z]+)=\"([^\"]+)\"");
        int i;
        String key, value;

        if (header == null || header.equals("")) {
            throw new IllegalStateException("missing value for Signature.");
        }
        header = header.trim();

        // In draft 01, the header was "Authorization" and it contained
        // the keyword "Signature" in uppercase. As of draft 03, the header
        // is "Signature" and it contains no such keyword.
        //
        // if (!s.startsWith("Signature ")) {
        //     throw new IllegalStateException("signature lacks Signature prefix.");
        // }
        // s = s.substring(10, publicKey.length());

        String[] parts = StringUtils.split(header,",");
        for(i=0; i< parts.length; i++) {
            Matcher m = re2.matcher(parts[i]);
            if (!m.matches()) {
                throw new IllegalStateException("the signature is malformed ("+parts[i]+")");
            }

            key = m.group(1);
            value = m.group(2);

            if (ArrayUtils.indexOf(knownSignatureItems,key) < 0) {
                throw new IllegalStateException("signature has unknown key ("+key+").");
            }
            if (key.equals("headers")) {
                props.put(key, StringUtils.split(value," "));
            }
            else {
                props.put(key, value);
            }
        }

        // validate that we have all required keys
        for(i=0; i< knownSignatureItems.length; i++) {
            key = knownSignatureItems[i];
            // only the "headers" key is optional
            if (!key.equals("headers")) {
                if (!props.containsKey(key)) {
                    throw new IllegalStateException("signature is missing key ("+key+").");
                }
                value = (String) props.get(key);
                if (value == null || value.equals("")) {
                    throw new IllegalStateException("signature has empty value for key ("+key+").");
                }
                // for the algorithm, we do a further check on validity
                if (key.equals("algorithm")) {
                    if (!supportedAlgorithms.containsKey(value)) {
                        throw new UnsupportedOperationException("unsupported algorithm: " + value);
                    }

                    this._isRsa = value.startsWith("rsa-");
                }
            }
        }
    }

    public HttpSignature(String s) throws IllegalStateException {
        parseHttpSignatureHeader(s);
    }
}
