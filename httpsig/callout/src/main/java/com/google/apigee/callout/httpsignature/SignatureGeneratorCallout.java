// SignatureGeneratorCallout.java
//
// A callout for Apigee that generates an HTTP Signature.
// See http://tools.ietf.org/html/draft-cavage-http-signatures-11 .
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
import com.google.apigee.util.TimeResolver;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@IOIntensive
public class SignatureGeneratorCallout extends CalloutBase implements Execution {
  public static final DateTimeFormatter DATE_FORMATTERS[] = {
    DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX"),
    DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss zzz"),
    DateTimeFormatter.ofPattern("EEEE, dd-MMM-yy HH:mm:ss zzz"),
    DateTimeFormatter.ofPattern("EEE MMM d HH:mm:ss yyyy"),
    DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSZ")
  };

  public SignatureGeneratorCallout(Map properties) {
    super(properties);
  }

  private String getDesiredAlgorithm(MessageContext msgCtxt) throws Exception {
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

    algorithm = PackageUtils.resolvePropertyValue(algorithm, msgCtxt);
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

    algorithm = PackageUtils.resolvePropertyValue(algorithm, msgCtxt);
    if (algorithm == null || algorithm.equals("")) {
      throw new IllegalStateException("hs2019-algorithm resolves to an empty string.");
    }
    return algorithm;
  }

  private String getKeyId(MessageContext msgCtxt) throws Exception {
    String keyId = (String) this.properties.get("keyId");
    if (keyId == null) {
      throw new IllegalStateException("keyId is not specified.");
    }
    keyId = keyId.trim();
    if (keyId.equals("")) {
      throw new IllegalStateException("keyId is not specified.");
    }

    keyId = PackageUtils.resolvePropertyValue(keyId, msgCtxt);
    if (keyId == null || keyId.equals("")) {
      throw new IllegalStateException("keyId resolves to an empty string.");
    }
    return keyId;
  }

  private List<String> getHeadersToSign(MessageContext msgCtxt) {
    return getHeaders(msgCtxt);
  }

  protected boolean getWantCreated(MessageContext msgCtxt) {
    String value = (String) this.properties.get("include-created");
    if (value == null) return false;
    if (value.trim().toLowerCase().equals("true")) return true;
    return false;
  }

  private String getExpiresIn(MessageContext msgCtxt) throws Exception {
    String expiresIn = (String) this.properties.get("expires-in");
    if (expiresIn == null) {
      return null;
    }
    expiresIn = expiresIn.trim();
    if (expiresIn.equals("")) {
      return null;
    }
    return PackageUtils.resolvePropertyValue(expiresIn, msgCtxt);
  }

  private void clearVariables(MessageContext msgCtxt) {
    msgCtxt.removeVariable(varName("error"));
    msgCtxt.removeVariable(varName("exception"));
    msgCtxt.removeVariable(varName("stacktrace"));
    msgCtxt.removeVariable(varName("desiredHeaders"));
    msgCtxt.removeVariable(varName("desiredAlgorithm"));
    msgCtxt.removeVariable(varName("signingBase"));
  }

  public ExecutionResult execute(MessageContext msgCtxt, ExecutionContext exeCtxt) {
    ExecutionResult result = ExecutionResult.ABORT;
    try {
      clearVariables(msgCtxt);

      // 1. retrieve the ordered list of headers to sign.
      List<String> headersToSign = getHeadersToSign(msgCtxt);
      if (headersToSign == null) {
        headersToSign = Arrays.asList(new String[] { REQUEST_TARGET });
      }

      // 2. get the desired algorithm
      String desiredAlgorithm = getDesiredAlgorithm(msgCtxt);
      msgCtxt.setVariable(varName("desiredAlgorithm"), desiredAlgorithm);
      if (!HttpSignature.isSupportedAlgorithm(desiredAlgorithm)) {
        throw new Exception("unsupported algorithm: " + desiredAlgorithm);
      }

      // 3. get the keyId - an arbitrary string
      String keyId = getKeyId(msgCtxt);

      // 4. get the effective times, created and expiry
      boolean wantCreateTime = getWantCreated(msgCtxt);
      String expiresIn = getExpiresIn(msgCtxt);

      // 4. produce the signature
      HttpSignature sig = HttpSignature.forGeneration(wantCreateTime, expiresIn);
      EdgeHeaderProvider hp = new EdgeHeaderProvider(msgCtxt);
      KeyProvider kp = new KeyProviderImpl(msgCtxt, properties);
      SigGenerationResult generation =
              sig.sign(
              desiredAlgorithm,
              headersToSign,
              hp,
              kp,
              () -> {
                return getRequiredHs2019Algorithm(msgCtxt);
              });
      msgCtxt.setVariable(varName("headers"), generation.headers);
      msgCtxt.setVariable(varName("signingBase"), generation.signingBase.replace('\n', '|'));
      msgCtxt.setVariable(varName("output"), generation.getSignatureHeader(keyId));
      msgCtxt.setVariable(varName("signature"), generation.computedSignature);
      result = ExecutionResult.SUCCESS;
    } catch (IllegalStateException exc1) {
      // if (getDebug()) {
      //     String stacktrace = PackageUtils.getStackTraceAsString(exc1);
      //     System.out.printf("%s\n", stacktrace);
      // }
      setExceptionVariables(exc1, msgCtxt);
      result = ExecutionResult.ABORT;
    } catch (Exception e) {
      if (getDebug()) {
        String stacktrace = PackageUtils.getStackTraceAsString(e);
        msgCtxt.setVariable(varName("stacktrace"), stacktrace);
      }
      setExceptionVariables(e, msgCtxt);
      result = ExecutionResult.ABORT;
    }

    return result;
  }
}
