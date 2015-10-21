package com.apigee.callout.httpsignature;

import java.io.InputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.nio.charset.StandardCharsets;

import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.NoSuchAlgorithmException;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.apigee.flow.message.Message;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.exception.ExceptionUtils;

import com.apigee.callout.httpsignature.HttpSignature;


@IOIntensive
public class SignatureParserCallout implements Execution {

    private Map properties; // read-only

    public SignatureParserCallout (Map properties) {
        this.properties = properties;
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
                if (uri.getQuery()!=null) { path += uri.getQuery(); }

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
        String varprefix = "httpsig";
        ExecutionResult result = ExecutionResult.ABORT;
        Boolean isValid = false;
        try {
            varName = varprefix + "_error";
            msgCtxt.setVariable(varName, null);
            // get the full signature header payload
            HttpSignature sigObject = getFullSignature(msgCtxt);

            // emit the 4 pieces into context variables
            varName = varprefix + "_algorithm";
            msgCtxt.setVariable(varName, sigObject.getAlgorithm());

            varName = varprefix + "_keyId";
            msgCtxt.setVariable(varName, sigObject.getKeyId());

            varName = varprefix + "_signature";
            msgCtxt.setVariable(varName, sigObject.getSignatureString());

            varName = varprefix + "_headers";
            msgCtxt.setVariable(varName, StringUtils.join(sigObject.getHeaders()," "));

            isValid = true;
            result = ExecutionResult.SUCCESS;
        }
        catch (Exception e) {
            //e.printStackTrace();
            varName = varprefix + "_error";
            msgCtxt.setVariable(varName, e.getMessage());
            varName = varprefix + "_stacktrace";
            msgCtxt.setVariable(varName, ExceptionUtils.getStackTrace(e));
        }

        varName = varprefix + "_isSuccess";
        msgCtxt.setVariable(varName, isValid);
        return result;
    }
}
