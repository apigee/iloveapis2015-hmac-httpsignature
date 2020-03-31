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

import com.google.apigee.util.TimeResolver;
import com.google.common.io.BaseEncoding;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.time.ZonedDateTime;
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
    private Map<String, Object> params = new HashMap<String, Object>();

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

    public static HttpSignature forVerification(String s) throws IllegalStateException {
        HttpSignature sig = new HttpSignature();
        sig.parseHttpSignatureString(s);
        sig._mode = Mode.VERIFYING;
        return sig;
    }

    public static HttpSignature forGeneration(boolean wantCreated, String expiresIn)
    {
        HttpSignature sig = new HttpSignature();
        if (wantCreated) {
            long now = ZonedDateTime.now().toEpochSecond();
            sig.params.put("created", (Integer) Math.toIntExact(now));

            if (expiresIn != null) {
                Long lifetimeInSeconds = TimeResolver.resolveExpression(expiresIn);
                sig.params.put("expires", (Integer) Math.toIntExact(now + lifetimeInSeconds));
            }
        }
        sig._mode = Mode.SIGNING;
        return sig;
    }

    private HttpSignature() { }

    enum Mode { UNSET, SIGNING, VERIFYING; }
    private Mode _mode = Mode.UNSET;

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
    public void setHeaders(List<String> value) { params.put("headers", value); }

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

        if (_mode != Mode.VERIFYING)
                throw new IllegalStateException("wrong mode");

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

    public SigGenerationResult sign(String algorithm,
                                           List<String> headersToSign,
                                           ReadOnlyHttpSigHeaderMap hmap,
                                           KeyProvider kp,
                                           Callable<String> hs2019AlgorithmSupplier)
        throws Exception {

        if (_mode != Mode.SIGNING)
            throw new IllegalStateException("wrong mode");

        if (supportedAlgorithms.containsKey(algorithm)) {
            String javaAlgoName = HttpSignature.supportedAlgorithms.get(algorithm);
            if (javaAlgoName.endsWith("withRSA")) {
                return signWithRsa(algorithm, javaAlgoName, headersToSign, hmap, kp);
            }
            else {
                return signWithHmac(algorithm, javaAlgoName, headersToSign, hmap, kp);
            }
        }
        else if (algorithm.equals("hs2019")) {
            String desiredFlavor = hs2019AlgorithmSupplier.call();
            if (desiredFlavor.equals("rsa")) {
                return signWithRsa(algorithm, "SHA512withRSA/PSS", headersToSign, hmap, kp);
            }
            else if (desiredFlavor.equals("hmac")) {
                return signWithHmac(algorithm, "HmacSHA512", headersToSign, hmap, kp);
            }
            else {
                throw new IllegalStateException("Unsupported algorithm");
            }
        }
        throw new IllegalStateException("Unsupported algorithm");
    }

    private SigGenerationResult setupSigning(String algorithm,
                                             List<String> headersToSign,
                                             ReadOnlyHttpSigHeaderMap hmap) {
        SigGenerationResult interimResult = new SigGenerationResult();
        this.params.put("algorithm", algorithm);
        interimResult.algorithm = algorithm;

        List<String> copy = new ArrayList<String>();
        copy.addAll(headersToSign);

        // insure created and expires are present if necessary
        if (null!=params.get("created") && !headersToSign.contains("created")) {
            copy.add("created");
            interimResult.created = (Integer) params.get("created");
        }
        if (null!=params.get("expires") && !headersToSign.contains("expires")) {
            copy.add("expires");
            interimResult.expires = (Integer) params.get("expires");
        }
        this.setHeaders(copy);
        interimResult.signingBase = this.getSigningBase(hmap);
        interimResult.headers = String.join(" ", copy);
        return interimResult;
    }

    private SigGenerationResult signWithHmac(String algorithm,
                                                    String javaAlgoName,
                                                    List<String> headersToSign,
                                                    ReadOnlyHttpSigHeaderMap hmap,
                                                    KeyProvider kp) throws Exception {
        SigGenerationResult result = setupSigning(algorithm, headersToSign, hmap);
        byte[] signingKey = kp.getSecretKey();
        SecretKeySpec key = new SecretKeySpec(signingKey, javaAlgoName);
        Mac hmac = Mac.getInstance(javaAlgoName);
        hmac.init(key);
        result.computedSignature =
            BaseEncoding.base64().encode( hmac.doFinal(result.signingBase.getBytes("UTF-8")) );
        return result;
    }

    private SigGenerationResult signWithRsa(String algorithm,
                                            String javaAlgoName,
                                            List<String> headersToSign,
                                            ReadOnlyHttpSigHeaderMap hmap,
                                            KeyProvider kp) throws Exception {
        SigGenerationResult result = setupSigning(algorithm, headersToSign, hmap);
        Signature sig = Signature.getInstance(javaAlgoName);
        PrivateKey privateKey = kp.getPrivateKey();
        sig.initSign(privateKey);
        sig.update(result.signingBase.getBytes(StandardCharsets.UTF_8));
        result.computedSignature =
            BaseEncoding.base64().encode( sig.sign() );
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
                if (!this.params.get("algorithm").equals("hs2019"))
                    throw new IllegalStateException("invalid parameter: created");
                v = this.getCreated().toString();
                name = "(created)";
            }
            else if (name.equals("expires")) {
                if (!this.params.get("algorithm").equals("hs2019"))
                    throw new IllegalStateException("invalid parameter: expires");
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
