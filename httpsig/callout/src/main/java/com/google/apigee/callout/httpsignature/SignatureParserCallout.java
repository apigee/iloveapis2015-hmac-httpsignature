package com.google.apigee.callout.httpsignature;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@IOIntensive
public class SignatureParserCallout extends CalloutBase implements Execution {
  private static final String SPECIAL_HEADER_VALUE = "(request-target)";

  public SignatureParserCallout(Map properties) {
    super(properties);
  }

  private String getSigningBase(MessageContext msgCtxt, HttpSignature sig)
      throws URISyntaxException {
    List<String> headers = sig.getHeaders();
    String sigBase = "";
    String path, v;

    if (headers == null) {
      headers = Collections.singletonList("date");
    }

    for (String header : headers) {
      if (!sigBase.equals("")) {
        sigBase += "\n";
      }
      if (header.equals(SPECIAL_HEADER_VALUE)) {
        // in HTTP Signature, the "path" includes the url path + query
        URI uri = new URI(msgCtxt.getVariable("proxy.url").toString());

        path = uri.getPath();
        if (uri.getQuery() != null) {
          path += uri.getQuery();
        }

        v = msgCtxt.getVariable("request.verb");
        if (v == null || v.equals("")) v = "unknown verb";
        sigBase += header + ": " + v.toLowerCase() + " " + path;
      } else {
        v = msgCtxt.getVariable("request.header." + header);
        if (v == null || v.equals("")) v = "unknown header " + header;
        sigBase += header + ": " + v;
      }
    }
    return sigBase;
  }

  private void clearVariables(MessageContext msgCtxt) {
    msgCtxt.removeVariable(varName("error"));
    msgCtxt.removeVariable(varName("exception"));
    msgCtxt.removeVariable(varName("stacktrace"));
    msgCtxt.removeVariable(varName("algorithm"));
    msgCtxt.removeVariable(varName("keyId"));
    msgCtxt.removeVariable(varName("signature"));
    msgCtxt.removeVariable(varName("headers"));
  }

  public ExecutionResult execute(MessageContext msgCtxt, ExecutionContext exeCtxt) {
    ExecutionResult result = ExecutionResult.ABORT;
    Boolean isValid = false;
    try {
      clearVariables(msgCtxt);
      // get the full signature header payload
      HttpSignature sigObject = getFullSignature(msgCtxt);

      // emit the 4 pieces into context variables
      msgCtxt.setVariable(varName("algorithm"), sigObject.getAlgorithm());
      msgCtxt.setVariable(varName("keyId"), sigObject.getKeyId());
      msgCtxt.setVariable(varName("signature"), sigObject.getSignatureString());
      msgCtxt.setVariable(varName("headers"), spaceJoiner.apply(sigObject.getHeaders()));

      isValid = true;
      result = ExecutionResult.SUCCESS;

    } catch (IllegalStateException exc1) {
      // if (getDebug()) {
      //     String stacktrace = PackageUtils.getStackTraceAsString(exc1);
      //     System.out.printf("\n** %s\n", stacktrace);
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

    msgCtxt.setVariable(varName("isSuccess"), isValid);
    msgCtxt.setVariable(varName("success"), isValid);
    return result;
  }
}
