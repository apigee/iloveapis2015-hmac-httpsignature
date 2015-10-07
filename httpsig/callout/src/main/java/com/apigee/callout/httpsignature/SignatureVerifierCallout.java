// SignatureVerifierCallout.java
//
// A callout for Apigee Edge that verifies an HTTP Signature.
// See http://tools.ietf.org/html/draft-cavage-http-signatures-04 .
//
// Thursday, 20 August 2015, 09:45
//
//
// This software is licensed under the MIT License (MIT)
//
// Copyright (c) 2015 by Dino Chiesa, Apigee Corporation
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//

package com.apigee.callout.httpsignature;

import java.io.InputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import java.util.Date;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.nio.charset.StandardCharsets;

// for RSA
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.NoSuchAlgorithmException;

// for HMAC
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

// for both
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.http.client.utils.DateUtils;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.apigee.flow.message.Message;


import com.apigee.callout.httpsignature.HttpSignature;

@IOIntensive
public class SignatureVerifierCallout implements Execution {

    private Map properties; // read-only

    public SignatureVerifierCallout (Map properties) {
        this.properties = properties;
    }

    private String getVarprefix() throws Exception {
        String varprefix = (String) this.properties.get("varprefix");
        if (varprefix == null || varprefix.equals("")) {
            return "httpsig"; // default prefix
        }
        return varprefix;
    }

    private String getRequiredAlgorithm(MessageContext msgCtxt) throws Exception {
        String algorithm = (String) this.properties.get("algorithm");
        if (algorithm == null) { return null; }
        algorithm = algorithm.trim();
        if (algorithm.equals("")) { return null; }

        algorithm = resolvePropertyValue(algorithm, msgCtxt);
        if (algorithm == null || algorithm.equals("")) {
            return null;
            // throw new IllegalStateException("algorithm resolves to an empty string.");
        }
        return algorithm;
    }

    private long getMaxTimeSkew(MessageContext msgCtxt) throws Exception {
        final long defaultMaxSkew = 60L;
        String timeskew = (String) this.properties.get("maxtimeskew");
        if (timeskew == null) { return defaultMaxSkew; }
        timeskew = timeskew.trim();
        if (timeskew.equals("")) { return defaultMaxSkew; }
        timeskew = resolvePropertyValue(timeskew, msgCtxt);
        if (timeskew == null || timeskew.equals("")) { return defaultMaxSkew; }
        return Long.parseLong(timeskew, 10);
    }

    private String[] getRequiredHeaders(MessageContext msgCtxt) /* throws Exception */ {
        String headers = (String) this.properties.get("headers");
        if (headers == null) { return null; }
        headers = headers.trim();
        if (headers.equals("")) { return null; }
        headers = resolvePropertyValue(headers, msgCtxt);
        if (headers == null || headers.equals("")) {
            // Question: is this an error?  I guess not.
            //throw new IllegalStateException("headers resolves to an empty string");
            return null;
        }
        return StringUtils.split(headers," ");
    }

    private long getRequestSecondsSinceEpoch(MessageContext msgCtxt)
        /* throws DateParseException */ {
        String dateString = msgCtxt.getVariable("request.header.date"); // Date header
        if (dateString == null) { return (new Date()).getTime()/1000L; } // now
        dateString = dateString.trim();
        if (dateString.equals("")) { return (new Date()).getTime()/1000L; } // now
        Date d1 = DateUtils.parseDate(dateString);
        long unixTime = d1.getTime() / 1000;
        return unixTime; // seconds since epoch
    }

    private String getMultivaluedHeader(MessageContext msgCtxt, String header) {
        String name = header + ".values";
        String separator = ",";
        ArrayList list = (ArrayList) msgCtxt.getVariable(name);
        String result= "";
        for (Object s : list) {
            result += (String) s + separator;
        }
        return result;
    }

    private HttpSignature getFullSignature(MessageContext msgCtxt)
        throws IllegalStateException {
        // consult the property first. If it is not present, retrieve the
        // request header.
        String signature = ((String) this.properties.get("fullsignature"));
        Boolean obtainedFromHeader = false;
        if (signature == null) {
            // In draft 01, the header was "Authorization".
            // As of draft 03, the header is "Signature".
            // NB: In Edge, getting a header that includes a comma requires getting
            // the .values, which is an ArrayList of strings.
            //
            signature = getMultivaluedHeader(msgCtxt,"request.header.signature");

            obtainedFromHeader = true;
            if (signature == null) {
                throw new IllegalStateException("signature is not specified.");
            }
        }
        signature = signature.trim();
        if (signature.equals("")) {
            throw new IllegalStateException("fullsignature is empty.");
        }
        if (!obtainedFromHeader) {
            signature = resolvePropertyValue(signature, msgCtxt);
            if (signature == null || signature.equals("")) {
                throw new IllegalStateException("fullsignature does not resolve.");
            }
        }
        HttpSignature httpsig = new HttpSignature(signature);
        return httpsig;
    }

    private static String getCleanEncodedKeyString(String publicKey)
        throws InvalidKeySpecException {
        publicKey = publicKey.trim();
        if (publicKey.startsWith("-----BEGIN RSA PUBLIC KEY-----") &&
            publicKey.endsWith("-----END RSA PUBLIC KEY-----")) {
            // figure PKCS#1
            publicKey = publicKey.substring(30, publicKey.length() - 28);
            publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A" + publicKey;
        }
        else if (publicKey.startsWith("-----BEGIN PUBLIC KEY-----") &&
            publicKey.endsWith("-----END PUBLIC KEY-----")) {
            // figure PKCS#8
            publicKey = publicKey.substring(26, publicKey.length() - 24);
        }
        else {
            throw new InvalidKeySpecException("invalid key format");
        }

        publicKey = publicKey.replaceAll("[\\r|\\n| ]","");
        return publicKey;
    }

    private static InputStream getResourceAsStream(String resourceName)
      throws IOException {
        // forcibly prepend a slash
        if (!resourceName.startsWith("/")) {
            resourceName = "/" + resourceName;
        }
        if (!resourceName.startsWith("/resources")) {
            resourceName = "/resources" + resourceName;
        }
        InputStream in = SignatureVerifierCallout.class.getResourceAsStream(resourceName);

        if (in == null) {
            throw new IOException("resource \"" + resourceName + "\" not found");
        }

        return in;
    }

    private PublicKey getPublicKey(MessageContext msgCtxt)
        throws IOException,
               NoSuchAlgorithmException,
               InvalidKeySpecException
    {
        byte[] keyBytes = null;
        String publicKey = (String) this.properties.get("public-key");
        if (publicKey==null) {
            String pemfile = (String) this.properties.get("pemfile");
            if (pemfile == null || pemfile.equals("")) {
                throw new IllegalStateException("configuration error: must specify pemfile or public-key when algorithm is RS*");
            }
            pemfile = resolvePropertyValue(pemfile, msgCtxt);
            if (pemfile == null || pemfile.equals("")) {
                throw new IllegalStateException("configuration error: pemfile resolves to nothing; invalid when algorithm is RS*");
            }

            InputStream in = getResourceAsStream(pemfile);
            keyBytes = new byte[in.available()];
            in.read(keyBytes);
            in.close();

            publicKey = new String(keyBytes, "UTF-8");
        }
        else {
            if (publicKey.equals("")) {
                throw new IllegalStateException("configuration error: public-key must be non-empty");
            }
            publicKey = resolvePropertyValue(publicKey, msgCtxt);
            if (publicKey==null || publicKey.equals("")) {
                throw new IllegalStateException("configuration error: public-key variable resolves to empty; invalid when algorithm is RS*");
            }
        }

        publicKey = getCleanEncodedKeyString(publicKey);
        keyBytes = Base64.decodeBase64(publicKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey key = keyFactory.generatePublic(spec);
        return key;
    }


    private String getSecretKey(MessageContext msgCtxt) throws IllegalStateException {
        String key = (String) this.properties.get("secret-key");
        if (key == null || key.equals("")) {
            throw new IllegalStateException("configuration error: secret-key is not specified or is empty.");
        }
        key = resolvePropertyValue(key, msgCtxt);
        if (key == null || key.equals("")) {
            throw new IllegalStateException("configuration error: secret-key is null or empty.");
        }
        return key;
    }


    // If the value of a property value begins and ends with curlies,
    // eg, {apiproxy.name}, then "resolve" the value by de-referencing
    // the context variable whose name appears between the curlies.
    private String resolvePropertyValue(String spec, MessageContext msgCtxt) {
        if (spec.startsWith("{") && spec.endsWith("}")) {
            String varname = spec.substring(1,spec.length() - 1);
            String value = msgCtxt.getVariable(varname);
            return value;
        }
        return spec;
    }

    private String getSigningBase(MessageContext msgCtxt, HttpSignature sig)
    throws URISyntaxException {
        String[] headers = sig.getHeaders();
        String specialValue = "(request-target)";
        String sigBase = "";

        String path, v;

        if (headers == null) {
            headers = new String[] { "date" };
        }

        for (int i=0; i < headers.length; i++) {
            if (!sigBase.equals("")) { sigBase += "\n";}
            String h = headers[i];
            if (h.equals(specialValue)) {
                // in HTTP Signature, the "path" includes the url path + query
                URI uri = new URI(msgCtxt.getVariable("proxy.url").toString());

                path = uri.getPath();
                if (uri.getQuery()!=null) { path += "?" + uri.getQuery(); }

                v = msgCtxt.getVariable("request.verb");
                if (v==null || v.equals("")) v = "unknown verb";
                sigBase += h + ": " + v.toLowerCase() + " " + path;
            }
            else {
                v = msgCtxt.getVariable("request.header."+ h);
                if (v==null || v.equals("")) v = "unknown header " + h;
                sigBase += h + ": " + v;
            }
        }
        return sigBase;
    }

    public ExecutionResult execute(MessageContext msgCtxt,
                                   ExecutionContext exeCtxt) {
        String varName;
        String varprefix = "unknown";
        ExecutionResult result = ExecutionResult.ABORT;
        Boolean isValid = false;
        try {
            varprefix = getVarprefix();
            // 1. retrieve and parse the full signature header payload
            HttpSignature sigObject = getFullSignature(msgCtxt);

            // 2. get the required algorithm, if specified,
            // and check that the actual algorithm in the sig is as required.
            String actualAlgorithm = sigObject.getAlgorithm();
            String requiredAlgorithm = getRequiredAlgorithm(msgCtxt);
            if (requiredAlgorithm != null) {
                varName = varprefix + "_requiredAlgorithm";
                msgCtxt.setVariable(varName, requiredAlgorithm);
                if (!HttpSignature.supportedAlgorithms.containsKey(requiredAlgorithm)) {
                    throw new Exception("unsupported algorithm: " + requiredAlgorithm);
                }

                if (!actualAlgorithm.equals(requiredAlgorithm)) {
                    throw new Exception("algorithm used in signature ("+ actualAlgorithm +") is not as required ("+ requiredAlgorithm +")");
                }
            }

            // 3. if there are any headers that are configured to be required,
            // check that they are all present in the sig.
            String[] requiredHeaders = getRequiredHeaders(msgCtxt);
            if (requiredHeaders != null) {
                varName = varprefix + "_requiredHeaders";
                msgCtxt.setVariable(varName, StringUtils.join(requiredHeaders," "));
                String[] actualHeaders = sigObject.getHeaders();
                int i;
                for (i=0; i < actualHeaders.length; i++) {
                    actualHeaders[i] = actualHeaders[i].toLowerCase();
                }
                for (i=0; i < requiredHeaders.length; i++) {
                    String h = requiredHeaders[i].toLowerCase();
                    if (ArrayUtils.indexOf(actualHeaders,h) < 0) {
                        throw new Exception("signature is missing required header ("+h+").");
                    }
                }
            }

            // 4. Verify that the date skew is within compliance
            long maxTimeSkew = getMaxTimeSkew(msgCtxt);
            if (maxTimeSkew > 0L) {
                long t1 = getRequestSecondsSinceEpoch(msgCtxt);
                long t2 = (new Date()).getTime() / 1000; // seconds since epoch
                long diff = Math.abs(t2 - t1);
                varName = varprefix + "_timeskew";
                msgCtxt.setVariable(varName, Long.toString(diff));
                if (diff > maxTimeSkew) {
                    // fail.
                    throw new Exception("date header exceeds max time skew ("+diff+">" + maxTimeSkew + ").");
                }
            }

            // 5. finally, verify the signature
            String signingBase = getSigningBase(msgCtxt, sigObject);
            varName = varprefix + "_signingBase";
            msgCtxt.setVariable(varName, signingBase.replace('\n','|'));

            String javaAlgoName = HttpSignature.supportedAlgorithms.get(actualAlgorithm);
            if (sigObject.isRsa()) {
                // RSA
                PublicKey publicKey = getPublicKey(msgCtxt);
                Signature sig = Signature.getInstance(javaAlgoName);
                sig.initVerify(publicKey);
                sig.update(signingBase.getBytes(StandardCharsets.UTF_8));
                byte[] signatureBytes = sigObject.getSignatureBytes();
                isValid = sig.verify(signatureBytes);
            }
            else {
                // HMAC
                String signingKey = getSecretKey(msgCtxt);
                varName = varprefix + "_signingKey";
                msgCtxt.setVariable(varName, signingKey);

                SecretKeySpec key = new SecretKeySpec(signingKey.getBytes("UTF-8"), javaAlgoName);
                Mac hmac = Mac.getInstance(javaAlgoName);
                hmac.init(key);

                String computedSignature = Base64.encodeBase64String(hmac.doFinal(signingBase.getBytes("UTF-8")));
                String providedSignature = sigObject.getSignatureString();
                isValid = computedSignature.equals(providedSignature);
                varName = varprefix + "_computedSignature";
                msgCtxt.setVariable(varName, computedSignature);
            }

            result = ExecutionResult.SUCCESS;
        }
        catch (Exception e) {
            e.printStackTrace();
            varName = varprefix + "_error";
            msgCtxt.setVariable(varName, e.getMessage());
            varName = varprefix + "_stacktrace";
            msgCtxt.setVariable(varName, ExceptionUtils.getStackTrace(e));
            result = ExecutionResult.ABORT;
        }

        varName = varprefix + "_isValid";
        msgCtxt.setVariable(varName, isValid);
        return result;
    }
}
