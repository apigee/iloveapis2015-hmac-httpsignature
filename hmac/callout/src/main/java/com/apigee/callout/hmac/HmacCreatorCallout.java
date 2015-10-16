package com.apigee.callout.hmac;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.HashMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.commons.lang.text.StrSubstitutor;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

import com.apigee.callout.hmac.TemplateString;

@IOIntensive
public class HmacCreatorCallout implements Execution {
    private static final String defaultAlgorithm = "SHA-256";
    private static final String TRUE = "true";
    //private static Pattern algPattern = Pattern.compile("^(?:(SHA)-?(1|224|256|384|512))|(?:(MD)-?(5))$", Pattern.CASE_INSENSITIVE);
    private static Pattern algMd5Pattern = Pattern.compile("^(MD)-?(5)$", Pattern.CASE_INSENSITIVE);
    private static Pattern algShaPattern = Pattern.compile("^(SHA)-?(1|224|256|384|512)$", Pattern.CASE_INSENSITIVE);

    private Map properties; // read-only

    public HmacCreatorCallout (Map properties) {
        this.properties = properties;
    }

    private String getStringToSign(MessageContext msgCtxt) throws Exception {
        String msg = (String) this.properties.get("string-to-sign");
        if (msg == null || msg.equals("")) {
            // by default, get the content of the message (either request or response)
            return msgCtxt.getVariable("message.content");
        }

        // replace ALL curly-braced items in the string-to-sign
        TemplateString ts = new TemplateString(msg);
        Map valuesMap = new HashMap();
        for (String s : ts.variableNames) {
            valuesMap.put(s, msgCtxt.getVariable(s));
        }
        StrSubstitutor sub = new StrSubstitutor(valuesMap);
        String resolvedString = sub.replace(ts.template);
        return resolvedString;
    }

    private String getKey(MessageContext msgCtxt) throws Exception {
        String key = (String) this.properties.get("key");
        if (key == null || key.equals("")) {
            throw new IllegalStateException("key is not specified or is empty.");
        }
        key = resolvePropertyValue(key, msgCtxt);
        if (key == null || key.equals("")) {
            throw new IllegalStateException("key is null or empty.");
        }
        return key;
    }

    private String getHmac(MessageContext msgCtxt) throws Exception {
        String hmac = (String) this.properties.get("hmac-base64");
        if (hmac == null || hmac.equals("")) {
            return null;
        }
        hmac = resolvePropertyValue(hmac, msgCtxt);
        if (hmac == null || hmac.equals("")) {
            throw new IllegalStateException("hmac-base64 resolves to null or empty.");
        }
        return hmac;
    }

    private boolean getDebug(MessageContext msgCtxt) throws Exception {
        String flag = (String) this.properties.get("debug");
        if (flag == null || flag.equals("")) {
            return false;
        }
        flag = resolvePropertyValue(flag, msgCtxt);
        if (flag == null || flag.equals("")) {
            return false;
        }
        return flag.equalsIgnoreCase(TRUE);
    }

    private String getAlgorithm(MessageContext msgCtxt) throws Exception {
        String alg = (String) this.properties.get("algorithm");
        if (alg == null || alg.equals("")) {
            return defaultAlgorithm;
        }
        alg = resolvePropertyValue(alg, msgCtxt);
        if (alg == null || alg.equals("")) {
            return defaultAlgorithm;
        }
        return alg;
    }

    // If the value of a property value begins and ends with curlies,
    // and contains no spaces, eg, {apiproxy.name}, then "resolve" the
    // value by de-referencing the context variable whose name appears
    // between the curlies.
    private String resolvePropertyValue(String spec, MessageContext msgCtxt) {
        if (spec.startsWith("{") && spec.endsWith("}") &&
            (spec.indexOf(" ") == -1)) {
            String varname = spec.substring(1,spec.length() - 1);
            String value = msgCtxt.getVariable(varname);
            return value;
        }
        return spec;
    }

    private static String javaizeAlgorithmName(MessageContext msgCtxt,String alg)
        throws IllegalStateException {
        Matcher m = algShaPattern.matcher(alg);
        if (!m.matches()) {
            m = algMd5Pattern.matcher(alg);
            if (!m.matches()) {
                throw new IllegalStateException("the algorithm name (" + alg + ") is not recognized");
            }
        }

        String stdName = m.group(1).toUpperCase() + m.group(2);
        return "Hmac" + stdName;
    }

    private void clearVariables(MessageContext msgCtxt) {
        msgCtxt.removeVariable("hmac.error");
        msgCtxt.removeVariable("hmac.stacktrace");
        msgCtxt.removeVariable("hmac.javaizedAlg");
        msgCtxt.removeVariable("hmac.alg");
        msgCtxt.removeVariable("hmac.string-to-sign");
        msgCtxt.removeVariable("hmac.signature.hex");
        msgCtxt.removeVariable("hmac.signature.b64");
    }

    public ExecutionResult execute(MessageContext msgCtxt,
                                   ExecutionContext exeCtxt) {
        try {
            clearVariables(msgCtxt);
            String signingKey = getKey(msgCtxt);
            String stringToSign = getStringToSign(msgCtxt);
            String algorithm = getAlgorithm(msgCtxt);
            boolean debug = getDebug(msgCtxt);
            msgCtxt.setVariable("hmac.alg", algorithm);

            String javaizedAlg = javaizeAlgorithmName(msgCtxt,algorithm);
            if (debug) {
                msgCtxt.setVariable("hmac.javaizedAlg", javaizedAlg);
            }

            Mac hmac = Mac.getInstance(javaizedAlg);
            SecretKeySpec key = new SecretKeySpec(signingKey.getBytes(), javaizedAlg);
            hmac.init(key);
            byte[] hmacBytes = hmac.doFinal(stringToSign.getBytes("UTF-8"));
            String sigHex = Hex.encodeHexString(hmacBytes);
            String sigB64 = Base64.encodeBase64String(hmacBytes);

            if (debug) {
                msgCtxt.setVariable("hmac.key", signingKey);
            }
            msgCtxt.setVariable("hmac.string-to-sign", stringToSign);
            msgCtxt.setVariable("hmac.signature.hex", sigHex);
            msgCtxt.setVariable("hmac.signature.b64", sigB64);

            // presence of hmac-base64 property indicates verification wanted
            String expectedHmac = getHmac(msgCtxt);
            if (expectedHmac !=null) {
                if (!sigB64.equals(expectedHmac)) {
                    msgCtxt.setVariable("hmac.error", "HMAC does not verify");
                    return ExecutionResult.ABORT;
                }
            }
        }
        catch (Exception e){
            msgCtxt.setVariable("hmac.error", e.getMessage());
            msgCtxt.setVariable("hmac.stacktrace", ExceptionUtils.getStackTrace(e));
            return ExecutionResult.ABORT;
        }
        return ExecutionResult.SUCCESS;
    }
}
