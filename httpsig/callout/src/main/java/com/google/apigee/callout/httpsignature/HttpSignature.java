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
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HttpSignature {
    private static final Splitter spaceSplitter = Splitter.on(' ').trimResults();
    private static final Splitter commaSplitter = Splitter.on(',').trimResults();
    private static final Pattern signatureElementPattern = Pattern.compile("([a-zA-z]+)=\"([^\"]+)\"");

    private Map<String, Object> props = new HashMap<String, Object>();

    // public static final Map<String, String> supportedRsaAlgorithms;
    // static {
    //     Map<String, String> a = new HashMap<String, String>();
    //     a.put("rsa-sha1", "SHA1withRSA");
    //     a.put("rsa-sha256", "SHA256withRSA");
    //     a.put("rsa-sha512", "SHA512withRSA");
    //     supportedRsaAlgorithms = Collections.unmodifiableMap(a);
    // }

    public static final Map<String, String> supportedAlgorithms;
    public static final List<String> knownSignatureItems;

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
        knownSignatureItems = Collections.unmodifiableList(list);
    }

    public HttpSignature(String s) throws IllegalStateException {
        parseHttpSignatureHeader(s);
    }

    public String getKeyId() { return (String) props.get("keyId"); }
    public void setKeyId(String value) { props.put("keyId", value); }

    public String getAlgorithm() { return (String) props.get("algorithm"); }
    public void setAlgorithm(String value) { props.put("algorithm", value); }

    public List<String> getHeaders() {
        if (!props.containsKey("headers")) { return null; }
        return (List<String>) props.get("headers");
    }
    public void setHeaders(String[] value) { props.put("headers", value); }

    public String getSignatureString() { return (String) props.get("signature"); }
    public byte[] getSignatureBytes() {
        return BaseEncoding .base64().decode((String) props.get("signature"));
    }
    public void setSignatureString(String value) { props.put("signature", value); }


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

            result.computedSignature =
                BaseEncoding.base64().encode( hmac.doFinal(result.signingBase.getBytes("UTF-8")) );

            String providedSignature = this.getSignatureString();
            result.isValid = result.computedSignature.equals(providedSignature);
        }
        return result;
    }

    public String getSigningBase(ReadOnlyHttpSigHeaderMap map) {
        List<String> headers = this.getHeaders();
        String sigBase = "";
        String path, v;

        if (headers == null) {
            headers = Collections.singletonList("date");
        }

        for (String header : headers) {
            if (!sigBase.equals("")) { sigBase += "\n";}
            v = map.getHeaderValue(header); // including special value
            if (v==null || v.equals("")) v = "unknown header " + header;
            sigBase += header + ": " + v;
        }
        return sigBase;
    }


    private void parseHttpSignatureHeader(String header)
        throws IllegalStateException, UnsupportedOperationException {
        int i;
        String key, value;

        if (header == null || header.equals("")) {
            throw new IllegalStateException("missing value for Signature.");
        }
        header = header.trim();

        // In draft 01, the header was "Authorization" and it contained the
        // keyword "Signature" in uppercase. As of draft 03, the header is
        // "Signature" and it contains no such keyword. We try to observe
        // Postel's law here.
        //
        if (header.toLowerCase().startsWith("signature ")) {
            header = header.substring(10, header.length());
        }

        Iterable<String> parts = commaSplitter.split(header);
        for(String part : parts) {
            Matcher m = signatureElementPattern.matcher(part);
            if (!m.matches()) {
                throw new IllegalStateException("the signature is malformed ("+part+")");
            }

            key = m.group(1);
            value = m.group(2);

            if (knownSignatureItems.indexOf(key) < 0) {
                throw new IllegalStateException("signature has unknown key ("+key+").");
            }
            if (key.equals("headers")) {
                props.put(key, spaceSplitter.splitToList(value));
            }
            else {
                props.put(key, value);
            }
        }

        // validate that we have all required keys
        for(String elementName : knownSignatureItems) {
            // only the "headers" key is optional
            if (!elementName.equals("headers")) {
                if (!props.containsKey(elementName)) {
                    throw new IllegalStateException("signature is missing key ("+elementName+").");
                }
                value = (String) props.get(elementName);
                if (value == null || value.equals("")) {
                    throw new IllegalStateException("signature has empty value for key ("+elementName+").");
                }
                // for the algorithm, we do a further check on validity
                if (elementName.equals("algorithm")) {
                    if (!supportedAlgorithms.containsKey(value)) {
                        throw new UnsupportedOperationException("unsupported algorithm: " + value);
                    }

                    this._isRsa = value.startsWith("rsa-");
                }
            }
        }
    }
}
