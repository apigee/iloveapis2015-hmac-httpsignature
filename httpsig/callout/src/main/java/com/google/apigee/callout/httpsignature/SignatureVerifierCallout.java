// SignatureVerifierCallout.java
//
// A callout for Apigee Edge that verifies an HTTP Signature.
// See http://tools.ietf.org/html/draft-cavage-http-signatures-04 .
//
// Copyright 2015-2020 Google LLC.
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
import com.apigee.flow.message.MessageContext;
import com.google.apigee.callout.httpsignature.KeyUtils.KeyParseException;
import com.google.apigee.util.TimeResolver;
import com.google.common.base.Splitter;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@IOIntensive
public class SignatureVerifierCallout extends CalloutBase implements Execution {
    private static final Splitter spaceSplitter = Splitter.on(' ').trimResults();
    public static final DateTimeFormatter DATE_FORMATTERS[] = {
        DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX"),
        DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss zzz"),
        DateTimeFormatter.ofPattern("EEEE, dd-MMM-yy HH:mm:ss zzz"),
        DateTimeFormatter.ofPattern("EEE MMM d HH:mm:ss yyyy"),
        DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSZ")
    };

    public SignatureVerifierCallout (Map properties) {
        super(properties);
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

    private String getRequiredHs2019Algorithm(MessageContext msgCtxt) throws Exception {
        String algorithm = (String) this.properties.get("hs2019-algorithm");
        if (algorithm == null) {
            throw new IllegalStateException("hs2019-algorithm is not specified.");
        }
        algorithm = algorithm.trim();
        if (algorithm.equals("")) {
            throw new IllegalStateException("hs2019-algorithm is not specified.");
        }

        algorithm = resolvePropertyValue(algorithm, msgCtxt);
        if (algorithm == null || algorithm.equals("")) {
            throw new IllegalStateException("hs2019-algorithm resolves to an empty string.");
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
        Long durationInSeconds = TimeResolver.resolveExpression(timeskew);
        return durationInSeconds;
    }

    private List<String> getRequiredHeaders(MessageContext msgCtxt) {
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
        return spaceSplitter.splitToList(headers);
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

    private class KeyProviderImpl implements KeyProvider {
        MessageContext c;

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

        public EdgeHeaderProvider(MessageContext msgCtxt) {
            c = msgCtxt;
        }

        public String getHeaderValue(String key) {
            String value = null;

            if (key.equals("(request-target)")) {
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
                value = c.getVariable("request.header."+ key);
            }
            return value;
        }
    }

    private void clearVariables(MessageContext msgCtxt) {
        msgCtxt.removeVariable(varName("error"));
        msgCtxt.removeVariable(varName("exception"));
        msgCtxt.removeVariable(varName("stacktrace"));
        msgCtxt.removeVariable(varName("requiredHeaders"));
        msgCtxt.removeVariable(varName("requiredAlgorithm"));
        msgCtxt.removeVariable(varName("timeskew"));
        msgCtxt.removeVariable(varName("signingBase"));
        msgCtxt.removeVariable(varName("isValid"));
    }

    public ExecutionResult execute(MessageContext msgCtxt, ExecutionContext exeCtxt) {
        ExecutionResult result = ExecutionResult.ABORT;
        Boolean isValid = false;
        try {
            clearVariables(msgCtxt);

            // 1. retrieve and parse the full signature header payload
            HttpSignature sig = getFullSignature(msgCtxt);

            // 2. get the required algorithm, if specified,
            // and check that the actual algorithm in the sig is as required.
            String actualAlgorithm = sig.getAlgorithm();
            String requiredAlgorithm = getRequiredAlgorithm(msgCtxt);

            msgCtxt.setVariable(varName("requiredAlgorithm"), requiredAlgorithm);
            if (!HttpSignature.isSupportedAlgorithm(requiredAlgorithm)) {
                throw new Exception("unsupported algorithm: " + requiredAlgorithm);
            }

            if (!actualAlgorithm.equals(requiredAlgorithm)) {
                throw new Exception("algorithm used in signature ("+ actualAlgorithm +") is not as required ("+ requiredAlgorithm +")");
            }

            // 3. if there are any headers that are configured to be required,
            // check that they are all present in the sig.
            List<String> requiredHeaders = getRequiredHeaders(msgCtxt);
            if (requiredHeaders != null) {
                msgCtxt.setVariable(varName("requiredHeaders"), spaceJoiner.apply(requiredHeaders));
                List<String> actualHeaders = sig.getHeaders()
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

            // 4. Verify that the date is in the past (allowing for skew)
            long maxTimeSkew = getMaxTimeSkew(msgCtxt);
            if (maxTimeSkew >= 0L) {
                long now = ZonedDateTime.now().toEpochSecond();
                // check that date is in the past, if it is included
                if (requiredHeaders.indexOf("date")>=0) {
                    long sentTime = getRequestSecondsSinceEpoch(msgCtxt);
                    if (sentTime > now + maxTimeSkew) {
                        throw new Exception("date header is in the future");
                    }
                }

                // check expires is in the future, if it is included
                if (sig.getHeaders().indexOf("expires")>=0) {
                    long expiry = (long) sig.getExpires();
                    if (expiry < now - maxTimeSkew) {
                        throw new Exception("the signature has expired");
                    }
                }
                // check expires is in the past, if it is included
                if (sig.getHeaders().indexOf("created")>=0) {
                    long created = (long) sig.getCreated();
                    if (created > now + maxTimeSkew) {
                        throw new Exception("the created time is in the future");
                    }
                }
            }

            // 5. finally, verify the signature
            EdgeHeaderProvider hp = new EdgeHeaderProvider(msgCtxt);
            KeyProvider kp = new KeyProviderImpl(msgCtxt);
            SigVerificationResult verification = sig.verify(actualAlgorithm, hp, kp, () -> {return getRequiredHs2019Algorithm(msgCtxt);} );
            isValid = verification.isValid;
            msgCtxt.setVariable(varName("signingBase"), verification.signingBase.replace('\n','|'));

            result = ExecutionResult.SUCCESS;
        } catch (IllegalStateException exc1) {
            if (getDebug()) {
                String stacktrace = getStackTraceAsString(exc1);
                System.out.printf("%s\n", stacktrace);
            }
            setExceptionVariables(exc1, msgCtxt);
            result = ExecutionResult.ABORT;
        } catch (Exception e) {
            if (getDebug()) {
                String stacktrace = getStackTraceAsString(e);
                System.out.printf("%s\n", stacktrace);
                msgCtxt.setVariable(varName("stacktrace"), stacktrace);
            }
            setExceptionVariables(e, msgCtxt);
            result = ExecutionResult.ABORT;
        }

        msgCtxt.setVariable(varName("isValid"), isValid);
        return result;
    }
}
