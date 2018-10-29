// SignatureVerifierCallout.java
//
// A callout for Apigee Edge that verifies an HTTP Signature.
// See http://tools.ietf.org/html/draft-cavage-http-signatures-04 .
//
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

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.Message;
import com.apigee.flow.message.MessageContext;
import com.google.apigee.callout.httpsignature.HttpSignature;
import com.google.apigee.callout.httpsignature.KeyUtils.KeyParseException;
import com.google.common.base.Joiner;
import com.google.common.base.Splitter;
import com.google.common.base.Throwables;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@IOIntensive
public class SignatureVerifierCallout implements Execution {
    private static final Joiner spaceJoiner = Joiner.on(' ');
    private static final Splitter spaceSplitter = Splitter.on(' ').trimResults();
    public static final DateTimeFormatter DATE_FORMATTERS[] = {
        DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX"),
        DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss zzz"),
        DateTimeFormatter.ofPattern("EEEE, dd-MMM-yy HH:mm:ss zzz"),
        DateTimeFormatter.ofPattern("EEE MMM d HH:mm:ss yyyy"),
        DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSZ")
    };

    private static final String _prefix = "httpsig_";

    private Map properties; // read-only

    public SignatureVerifierCallout (Map properties) {
        this.properties = properties;
    }

    private static String varName(String s) {
        return _prefix + s;
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

    private Iterable<String> getRequiredHeaders(MessageContext msgCtxt)
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
        return spaceSplitter.split(headers);
    }

    private static ZonedDateTime parseDate(String dateString) {
        if (dateString == null) return null;
        for (DateTimeFormatter formatter : DATE_FORMATTERS) {
            try {
                return ZonedDateTime.parse(dateString,formatter);
            } catch (DateTimeParseException ex) {
            }
        }
        return null;
    }

    private long getRequestSecondsSinceEpoch(MessageContext msgCtxt) {
        String dateString = msgCtxt.getVariable("request.header.date"); // Date header
        ZonedDateTime d1 = ZonedDateTime.now();
        if (dateString != null) {
            dateString = dateString.trim();
            if (!dateString.equals("")) {
              d1 = parseDate(dateString);
            }
        }
        return d1.toEpochSecond(); 
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
                   CertificateException,
                   KeyParseException
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
                try {
                    return KeyUtils.decodePublicKey(publicKeyString);
                }
                catch (KeyParseException ex) {
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
        ExecutionResult result = ExecutionResult.ABORT;
        Boolean isValid = false;
        try {
            msgCtxt.setVariable(varName("error"), null);

            // 1. retrieve and parse the full signature header payload
            HttpSignature sigObject = getFullSignature(msgCtxt);

            // 2. get the required algorithm, if specified,
            // and check that the actual algorithm in the sig is as required.
            String actualAlgorithm = sigObject.getAlgorithm();
            String requiredAlgorithm = getRequiredAlgorithm(msgCtxt);

            msgCtxt.setVariable(varName("requiredAlgorithm"), requiredAlgorithm);
            if (!HttpSignature.supportedAlgorithms.containsKey(requiredAlgorithm)) {
                throw new Exception("unsupported algorithm: " + requiredAlgorithm);
            }

            if (!actualAlgorithm.equals(requiredAlgorithm)) {
                throw new Exception("algorithm used in signature ("+ actualAlgorithm +") is not as required ("+ requiredAlgorithm +")");
            }

            // 3. if there are any headers that are configured to be required,
            // check that they are all present in the sig.
            Iterable<String> requiredHeaders = getRequiredHeaders(msgCtxt);
            if (requiredHeaders != null) {
                msgCtxt.setVariable(varName("requiredHeaders"), spaceJoiner.join(requiredHeaders));
                List<String> actualHeaders = sigObject.getHeaders()
                    .stream()
                    .map(String::toLowerCase)
                    .collect(Collectors.toList());

                for (String header : requiredHeaders) {
                    header = header.toLowerCase();
                    if (actualHeaders.indexOf(header) < 0) {
                        throw new Exception("signature is missing required header ("+header+").");
                    }
                }
            }

            // 4. Verify that the date skew is within compliance
            long maxTimeSkew = getMaxTimeSkew(msgCtxt);
            if (maxTimeSkew > 0L) {
                long t1 = getRequestSecondsSinceEpoch(msgCtxt);
                long t2 = ZonedDateTime.now().toEpochSecond();
                long diff = Math.abs(t2 - t1);
                msgCtxt.setVariable(varName("timeskew"), Long.toString(diff));
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
            msgCtxt.setVariable(varName("signingBase"), verification.signingBase.replace('\n','|'));

            result = ExecutionResult.SUCCESS;
        }
        catch (Exception e) {
            //System.out.printf(Throwables.getStackTraceAsString(e));

            msgCtxt.setVariable(varName("error"), e.getMessage());
            msgCtxt.setVariable(varName("stacktrace"), Throwables.getStackTraceAsString(e));
            result = ExecutionResult.ABORT;
        }

        msgCtxt.setVariable(varName("isValid"), isValid);
        return result;
    }
}
