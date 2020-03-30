// HttpSignature.java
// ------------------------------------------------------------------
//
// Copyright 2015-2018 Google LLC.
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

import com.google.common.base.Splitter;
import com.google.common.io.BaseEncoding;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HttpSignature {
    private static final Splitter spaceSplitter = Splitter.on(' ').trimResults();
    //private static final Splitter commaSplitter = Splitter.on(',').trimResults();
    private static final Pattern signatureElementPattern = Pattern.compile("([a-zA-z]+)=\"([^\"]+)\"");

    private Map<String, Object> params = new HashMap<String, Object>();

    // public static final Map<String, String> supportedRsaAlgorithms;
    // static {
    //     Map<String, String> a = new HashMap<String, String>();
    //     a.put("rsa-sha1", "SHA1withRSA");
    //     a.put("rsa-sha256", "SHA256withRSA");
    //     a.put("rsa-sha512", "SHA512withRSA");
    //     supportedRsaAlgorithms = Collections.unmodifiableMap(a);
    // }

    private static final Map<String, String> supportedAlgorithms;
    private static final List<String> knownSignatureItems;

    static {
        Map<String, String> map = new HashMap<String, String>();
        map.put("rsa-sha1", "SHA1withRSA");
        map.put("rsa-sha256", "SHA256withRSA");
        map.put("rsa-sha512", "SHA512withRSA");
        map.put("hmac-sha1", "HmacSHA1");
        map.put("hmac-sha256", "HmacSHA256");
        map.put("hmac-sha512", "HmacSHA512");
        supportedAlgorithms = Collections.unmodifiableMap(map);

        List<String> list = new ArrayList<String>();
        list.add("keyId");
        list.add("algorithm");
        list.add("headers");
        list.add("signature");
        list.add("created");
        list.add("expires");
        knownSignatureItems = Collections.unmodifiableList(list);
    }

    public static boolean isSupportedAlgorithm(String alg){
        return alg.equals("hs2019") || supportedAlgorithms.containsKey(alg);
    }

    public HttpSignature(String s) throws IllegalStateException {
        parseHttpSignatureString(s);
    }

    public Integer getCreated() { return (Integer) params.get("created"); }
    public Integer getExpires() { return (Integer) params.get("expires"); }

    public String getKeyId() { return (String) params.get("keyId"); }
    public void setKeyId(String value) { params.put("keyId", value); }

    public String getAlgorithm() { return (String) params.get("algorithm"); }
    public void setAlgorithm(String value) { params.put("algorithm", value); }

    public List<String> getHeaders() {
        if (!params.containsKey("headers")) { return null; }
        return (List<String>) params.get("headers");
    }
    public void setHeaders(String[] value) { params.put("headers", value); }

    public String getSignatureString() { return (String) params.get("signature"); }
    public byte[] getSignatureBytes() {
        return BaseEncoding .base64().decode((String) params.get("signature"));
    }
    public void setSignatureString(String value) { params.put("signature", value); }

    private boolean _isRsa = false;
    public boolean isRsa() {
        return _isRsa;
    }
    public boolean isHmac() {
        return !_isRsa;
    }

    public SigVerificationResult verify(String algorithm,
                                        ReadOnlyHttpSigHeaderMap hmap,
                                        KeyProvider kp,
                                        Callable<String> hs2019AlgorithmSupplier)
        throws Exception {

        if (supportedAlgorithms.containsKey(algorithm)) {
            String javaAlgoName = HttpSignature.supportedAlgorithms.get(algorithm);
            return (this.isRsa()) ?
                verifyWithRsa(javaAlgoName, hmap, kp) :
                verifyWithHmac(javaAlgoName, hmap, kp);
        }
        else if (algorithm.equals("hs2019")) {
            String desiredFlavor = hs2019AlgorithmSupplier.call();
            if (desiredFlavor.equals("rsa")) {
                return verifyWithRsa("SHA512withRSA/PSS", hmap, kp);
            }
            else if (desiredFlavor.equals("hmac")) {
                return verifyWithHmac("HmacSHA512", hmap, kp);
            }
            else {
                throw new IllegalStateException("Unsupported algorithm");
            }
        }
        throw new IllegalStateException("Unsupported algorithm");
    }

    private SigVerificationResult verifyWithHmac(String javaAlgoName,
                                                 ReadOnlyHttpSigHeaderMap hmap,
                                                 KeyProvider kp) throws Exception {
        SigVerificationResult result = new SigVerificationResult();
        result.signingBase = this.getSigningBase(hmap);
        result.isValid = false;
        byte[] signingKey = kp.getSecretKey();
        SecretKeySpec key = new SecretKeySpec(signingKey, javaAlgoName);
        Mac hmac = Mac.getInstance(javaAlgoName);
        hmac.init(key);
        result.computedSignature =
            BaseEncoding.base64().encode( hmac.doFinal(result.signingBase.getBytes("UTF-8")) );
        String providedSignature = this.getSignatureString();
        result.isValid = result.computedSignature.equals(providedSignature);
        return result;
    }

    private SigVerificationResult verifyWithRsa(String javaAlgoName,
                                  ReadOnlyHttpSigHeaderMap hmap,
                                  KeyProvider kp) throws Exception {
        SigVerificationResult result = new SigVerificationResult();
        result.signingBase = this.getSigningBase(hmap);
        result.isValid = false;
        PublicKey publicKey = kp.getPublicKey();
        Signature sig = Signature.getInstance(javaAlgoName);
        sig.initVerify(publicKey);
        sig.update(result.signingBase.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = this.getSignatureBytes();
        result.isValid = sig.verify(signatureBytes);
        return result;
    }

    public String getSigningBase(ReadOnlyHttpSigHeaderMap map) {
        List<String> headers = this.getHeaders();
        String sigBase = "";
        String v;

        if (headers == null) {
            headers = Collections.singletonList("date");
        }

        for (String name : headers) {
            if (!sigBase.equals("")) { sigBase += "\n";}
            if (name.equals("created")) {
                v = this.getCreated().toString();
                name = "(created)";
            }
            else if (name.equals("expires")) {
                v = this.getExpires().toString();
                name = "(expires)";
            }
            else {
                v = map.getHeaderValue(name); // also supports (request-target)
                if (v==null || v.equals("")) v = "unknown header " + name;
            }
            sigBase += name + ": " + v;
        }
        return sigBase;
    }

    private void parseHttpSignatureString(String str) throws IllegalStateException {
        try {
            params = SignatureParser.parse(str);
        }
        catch (Exception ex1) {
            throw new IllegalStateException("the signature is malformed: " + ex1.getMessage());
        }
        if (((String)(params.get("algorithm"))).startsWith("rsa")) {
            _isRsa = true;
        }
    }
}
