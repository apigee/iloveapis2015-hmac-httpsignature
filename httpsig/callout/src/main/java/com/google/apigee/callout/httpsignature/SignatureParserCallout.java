package com.google.apigee.callout.httpsignature;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.Message;
import com.apigee.flow.message.MessageContext;
import com.google.apigee.callout.httpsignature.HttpSignature;
import com.google.common.base.Joiner;
import com.google.common.base.Throwables;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@IOIntensive
public class SignatureParserCallout implements Execution {
    private final static String variableReferencePatternString = "(.*?)\\{([^\\{\\} ]+?)\\}(.*?)";
    private final static Pattern variableReferencePattern = Pattern.compile(variableReferencePatternString);
    private static final Joiner spaceJoiner = Joiner.on(' ');
    private static final Joiner commaJoiner = Joiner.on(',');
    private static final String _prefix = "httpsig_";
    private final static String SPECIAL_HEADER_VALUE = "(request-target)";

    private Map properties; // read-only

    public SignatureParserCallout (Map properties) {
        this.properties = properties;
    }

    private static String varName(String s) {
        return _prefix + s;
    }

    private String getMultivaluedHeader(MessageContext msgCtxt, String header) {
        String name = header + ".values";
        ArrayList list = (ArrayList) msgCtxt.getVariable(name);
        return commaJoiner.join(list);
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
            //
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

    // If the value of a property contains a pair of curlies,
    // eg, {apiproxy.name}, then "resolve" the value by de-referencing
    // the context variable whose name appears between the curlies.
    // If the variable name is not known, then it returns a null.
    private String resolvePropertyValue(String spec, MessageContext msgCtxt) {
        Matcher matcher = variableReferencePattern.matcher(spec);
        StringBuffer sb = new StringBuffer();
        while (matcher.find()) {
            matcher.appendReplacement(sb, "");
            sb.append(matcher.group(1));
            Object v = msgCtxt.getVariable(matcher.group(2));
            if (v != null){
                sb.append((String) v );
            }
            sb.append(matcher.group(3));
        }
        matcher.appendTail(sb);
        return (sb.length() > 0) ? sb.toString() : null;
    }

    private String getSigningBase(MessageContext msgCtxt, HttpSignature sig)
    throws URISyntaxException {
        List<String> headers = sig.getHeaders();
        String sigBase = "";
        String path, v;

        if (headers == null) {
            headers = Collections .singletonList("date");
        }

        for (String header : headers) {
            if (!sigBase.equals("")) { sigBase += "\n";}
            if (header.equals(SPECIAL_HEADER_VALUE)) {
                // in HTTP Signature, the "path" includes the url path + query
                URI uri = new URI(msgCtxt.getVariable("proxy.url").toString());

                path = uri.getPath();
                if (uri.getQuery()!=null) { path += uri.getQuery(); }

                v = msgCtxt.getVariable("request.verb");
                if (v==null || v.equals("")) v = "unknown verb";
                sigBase += header + ": " + v.toLowerCase() + " " + path;
            }
            else {
                v = msgCtxt.getVariable("request.header."+ header);
                if (v==null || v.equals("")) v = "unknown header " + header;
                sigBase += header + ": " + v;
            }
        }
        return sigBase;
    }

    public ExecutionResult execute(MessageContext msgCtxt,
                                   ExecutionContext exeCtxt) {
        String varName;
        ExecutionResult result = ExecutionResult.ABORT;
        Boolean isValid = false;
        try {
            msgCtxt.setVariable(varName("error"), null);
            // get the full signature header payload
            HttpSignature sigObject = getFullSignature(msgCtxt);

            // emit the 4 pieces into context variables
            msgCtxt.setVariable(varName("algorithm"), sigObject.getAlgorithm());
            msgCtxt.setVariable(varName("keyId"), sigObject.getKeyId());
            msgCtxt.setVariable(varName("signature"), sigObject.getSignatureString());
            msgCtxt.setVariable(varName("headers"), spaceJoiner.join(sigObject.getHeaders()));

            isValid = true;
            result = ExecutionResult.SUCCESS;
        }
        catch (Exception e) {
            //e.printStackTrace();
            msgCtxt.setVariable(varName("error"), e.getMessage());
            msgCtxt.setVariable(varName("stacktrace"), Throwables.getStackTraceAsString(e));
        }

        msgCtxt.setVariable(varName("isSuccess"), isValid);
        msgCtxt.setVariable(varName("success"), isValid);
        return result;
    }
}