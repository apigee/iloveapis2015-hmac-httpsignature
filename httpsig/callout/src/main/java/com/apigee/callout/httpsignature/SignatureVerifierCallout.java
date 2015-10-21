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

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.apigee.flow.message.Message;

import java.io.InputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import java.util.Date;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;

// for RSA
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.http.client.utils.DateUtils;


import com.apigee.callout.httpsignature.HttpSignature;

@IOIntensive
public class SignatureVerifierCallout implements Execution {

    private Map properties; // read-only

    public SignatureVerifierCallout (Map properties) {
        this.properties = properties;
    }

    private String getRequiredAlgorithm(MessageContext msgCtxt) throws Exception {
        String algorithm = (String) this.properties.get("algorithm");
        if (algorithm == null) {
            // to prevent attacks, ALWAYS require an algorithm
            throw new IllegalStateException("algorithm is not specified.");
        }
        algorithm = algorithm.trim();
        if (algorithm.equals("")) {
            // to prevent attacks, ALWAYS require an algorithm
            throw new IllegalStateException("algorithm is not specified.");
        }

        algorithm = resolvePropertyValue(algorithm, msgCtxt);
        if (algorithm == null || algorithm.equals("")) {
            throw new IllegalStateException("algorithm resolves to an empty string.");
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

    private String[] getRequiredHeaders(MessageContext msgCtxt)
        /* throws Exception */ {
        String headers = (String) this.properties.get("headers");
        if (headers == null) { return null; }
        headers = headers.trim();
        if (headers.equals("")) { return null; }
        headers = resolvePropertyValue(headers, msgCtxt);
        if (headers == null || headers.equals("")) {
            // Uncomment the below to force configuration to require a
            // headers property
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



    // If the value of a property value begins and ends with curlies,
    // and has no intervening spaces, eg, {apiproxy.name}, then
    // "resolve" the value by de-referencing the context variable whose
    // name appears between the curlies.
    private String resolvePropertyValue(String spec, MessageContext msgCtxt) {
        if (spec.startsWith("{") && spec.endsWith("}") && (spec.indexOf(" ") == -1)) {
            String varname = spec.substring(1,spec.length() - 1);
            String value = msgCtxt.getVariable(varname);
            return value;
        }
        return spec;
    }

    private class KeyProviderImpl implements KeyProvider {
        MessageContext c;
        private final static String specialValue = "(request-target)";

        public KeyProviderImpl(MessageContext msgCtxt) {
            c = msgCtxt;
        }

        public String getSecretKey() throws IllegalStateException {
            String key = (String) properties.get("secret-key");
            if (key == null || key.equals("")) {
                throw new IllegalStateException("configuration error: secret-key is not specified or is empty.");
            }
            key = resolvePropertyValue(key, c);
            if (key == null || key.equals("")) {
                throw new IllegalStateException("configuration error: secret-key is null or empty.");
            }
            return key;
        }


        public PublicKey getPublicKey( )
            throws IOException,
                   NoSuchAlgorithmException,
                   InvalidKeySpecException,
                   CertificateException
        {
            String publicKeyString = (String) properties.get("public-key");

            // There are various ways to specify the public key.

            // Try "public-key"
            if (publicKeyString !=null) {
                if (publicKeyString.equals("")) {
                    throw new IllegalStateException("public-key must be non-empty");
                }
                publicKeyString = resolvePropertyValue(publicKeyString, c);

                if (publicKeyString==null || publicKeyString.equals("")) {
                    throw new IllegalStateException("public-key variable resolves to empty; invalid when algorithm is RS*");
                }
                PublicKey key = KeyUtils.publicKeyStringToPublicKey(publicKeyString);
                if (key==null) {
                    throw new InvalidKeySpecException("must be PKCS#1 or PKCS#8");
                }
                return key;
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
            //         throw new IllegalStateException("modulus or exponent resolves to empty; invalid when algorithm is RS*");
            //     }
            //
            //     PublicKey key = KeyUtils.pubKeyFromModulusAndExponent(modulus, exponent);
            //     return key;
            // }

            // Try certificate
            String certString = (String) properties.get("certificate");
            if (certString !=null) {
                if (certString.equals("")) {
                    throw new IllegalStateException("certificate must be non-empty");
                }
                certString = resolvePropertyValue(certString, c);
                //msgCtxt.setVariable("jwt_certstring", certString);
                if (certString==null || certString.equals("")) {
                    throw new IllegalStateException("certificate variable resolves to empty; invalid when algorithm is RS*");
                }
                PublicKey key = KeyUtils.certStringToPublicKey(certString);
                if (key==null) {
                    throw new InvalidKeySpecException("invalid certificate format");
                }
                return key;
            }

            // last chance
            String pemfile = (String) properties.get("pemfile");
            if (pemfile == null || pemfile.equals("")) {
                throw new IllegalStateException("must specify pemfile or public-key or certificate when algorithm is RS*");
            }
            pemfile = resolvePropertyValue(pemfile, c);
            //msgCtxt.setVariable("jwt_pemfile", pemfile);
            if (pemfile == null || pemfile.equals("")) {
                throw new IllegalStateException("pemfile resolves to nothing; invalid when algorithm is RS*");
            }

            InputStream in = getResourceAsStream(pemfile);
            byte[] keyBytes = new byte[in.available()];
            in.read(keyBytes);
            in.close();
            publicKeyString = new String(keyBytes, "UTF-8");

            // allow pemfile resolution as Certificate or Public Key
            PublicKey key = KeyUtils.pemFileStringToPublicKey(publicKeyString);
            if (key==null) {
                throw new InvalidKeySpecException("invalid pemfile format");
            }
            return key;
        }

    }


    private class EdgeHeaderProvider implements ReadOnlyHttpSigHeaderMap {
        MessageContext c;
        private final static String specialValue = "(request-target)";

        public EdgeHeaderProvider(MessageContext msgCtxt) {
            c = msgCtxt;
        }

        public String getHeaderValue(String header) {
            String value = null;

            if (header.equals(specialValue)) {
                try {
                    // in HTTP Signature, the "path" includes the url path + query
                    URI uri = new URI(c.getVariable("proxy.url").toString());

                    String path = uri.getPath();
                    if (uri.getQuery()!=null) { path += "?" + uri.getQuery(); }

                    value = c.getVariable("request.verb");
                    if (value==null || value.equals("")) value = "unknown verb";
                    value = value.toLowerCase() + " " + path;

                }
                catch (URISyntaxException exc1) {
                    value = "none";
                }
            }
            else {
                value = c.getVariable("request.header."+ header);
            }
            return value;
        }
    }

    public ExecutionResult execute(MessageContext msgCtxt,
                                   ExecutionContext exeCtxt) {
        String varName;
        String varprefix = "httpsig";
        ExecutionResult result = ExecutionResult.ABORT;
        Boolean isValid = false;
        try {
            varName = varprefix + "_error";
            msgCtxt.setVariable(varName, null);

            // 1. retrieve and parse the full signature header payload
            HttpSignature sigObject = getFullSignature(msgCtxt);

            // 2. get the required algorithm, if specified,
            // and check that the actual algorithm in the sig is as required.
            String actualAlgorithm = sigObject.getAlgorithm();
            String requiredAlgorithm = getRequiredAlgorithm(msgCtxt);

            varName = varprefix + "_requiredAlgorithm";
            msgCtxt.setVariable(varName, requiredAlgorithm);
            if (!HttpSignature.supportedAlgorithms.containsKey(requiredAlgorithm)) {
                throw new Exception("unsupported algorithm: " + requiredAlgorithm);
            }

            if (!actualAlgorithm.equals(requiredAlgorithm)) {
                throw new Exception("algorithm used in signature ("+ actualAlgorithm +") is not as required ("+ requiredAlgorithm +")");
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
            EdgeHeaderProvider hp = new EdgeHeaderProvider(msgCtxt);
            KeyProvider kp = new KeyProviderImpl(msgCtxt);
            SigVerificationResult verification = sigObject.verify(actualAlgorithm, hp, kp);
            isValid = verification.isValid;
            varName = varprefix + "_signingBase";
            msgCtxt.setVariable(varName, verification.signingBase.replace('\n','|'));

            result = ExecutionResult.SUCCESS;
        }
        catch (Exception e) {
            //e.printStackTrace();
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
