package com.apigee.callout.hmac;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import java.io.StringWriter;
import java.io.PrintWriter;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
//import com.google.common.io.BaseEncoding;
//import com.google.common.base.Throwables;

@IOIntensive
public class HmacCreatorCallout implements Execution {
    private static final String varnamePrefix = "hmac.";
    private static final String defaultAlgorithm = "SHA-256";
    private static final String TRUE = "true";
    //private static Pattern algPattern = Pattern.compile("^(?:(SHA)-?(1|224|256|384|512))|(?:(MD)-?(5))$", Pattern.CASE_INSENSITIVE);
    private static final Pattern algMd5Pattern = Pattern.compile("^(MD)-?(5)$", Pattern.CASE_INSENSITIVE);
    private static final Pattern algShaPattern = Pattern.compile("^(SHA)-?(1|224|256|384|512)$", Pattern.CASE_INSENSITIVE);
    private static final String variableReferencePatternString = "(.*?)\\{([^\\{\\} ]+?)\\}(.*?)";
    private static final Pattern variableReferencePattern = Pattern.compile(variableReferencePatternString);
private static final Base64.Encoder base64Encoder = Base64.getEncoder();
private static final Base64.Encoder base64UrlEncoder = Base64.getUrlEncoder();

    private Map properties; // read-only

    public HmacCreatorCallout (Map properties) {
        this.properties = Collections.unmodifiableMap(properties);
    }

    private static String varName(String base) {
        return varnamePrefix + base;
    }

    private String getStringToSign(MessageContext msgCtxt) throws Exception {
        String msg = (String) this.properties.get("string-to-sign");
        if (msg == null || msg.equals("")) {
            // by default, get the content of the message (either request or response)
            return msgCtxt.getVariable("message.content");
        }
        String resolvedString = resolvePropertyValue(msg,msgCtxt);
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

    private String getExpectedHmac(MessageContext msgCtxt) throws Exception {
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

    // If the value of a property contains any pairs of curlies,
    // eg, {apiproxy.name}, then "resolve" the value by de-referencing
    // the context variables whose names appear between curlies.
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
        return sb.toString();
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
        msgCtxt.removeVariable(varName("error"));
        msgCtxt.removeVariable(varName("stacktrace"));
        msgCtxt.removeVariable(varName("javaizedAlg"));
        msgCtxt.removeVariable(varName("alg"));
        msgCtxt.removeVariable(varName("string-to-sign"));
        msgCtxt.removeVariable(varName("signature.hex"));
        msgCtxt.removeVariable(varName("signature.b64"));
        msgCtxt.removeVariable(varName("signature.b64url"));
    }

    public ExecutionResult execute(MessageContext msgCtxt,
                                   ExecutionContext exeCtxt) {
        try {
            clearVariables(msgCtxt);
            String signingKey = getKey(msgCtxt);
            String stringToSign = getStringToSign(msgCtxt);
            String algorithm = getAlgorithm(msgCtxt);
            boolean debug = getDebug(msgCtxt);
            msgCtxt.setVariable(varName("alg"), algorithm);

            String javaizedAlg = javaizeAlgorithmName(msgCtxt,algorithm);
            if (debug) {
                msgCtxt.setVariable(varName("javaizedAlg"), javaizedAlg);
            }

            Mac hmac = Mac.getInstance(javaizedAlg);
            SecretKeySpec key = new SecretKeySpec(signingKey.getBytes(), javaizedAlg);
            hmac.init(key);
            byte[] hmacBytes = hmac.doFinal(stringToSign.getBytes("UTF-8"));
            String sigHex = HexEncoder.encodeToString(hmacBytes);
            String sigB64 = base64Encoder.encodeToString(hmacBytes);
            String sigB64Url = base64UrlEncoder.encodeToString(hmacBytes);

            if (debug) {
                msgCtxt.setVariable(varName("key"), signingKey);
            }
            msgCtxt.setVariable(varName("string-to-sign"), stringToSign);
            msgCtxt.setVariable(varName("signature.hex"), sigHex);
            msgCtxt.setVariable(varName("signature.b64"), sigB64);
            msgCtxt.setVariable(varName("signature.b64url"), sigB64Url);

            // presence of hmac-base64 property indicates verification wanted
            String expectedHmac = getExpectedHmac(msgCtxt);
            if (expectedHmac !=null) {
                if (!sigB64.equals(expectedHmac)) {
                    msgCtxt.setVariable(varName("error"), "HMAC does not verify");
                    return ExecutionResult.ABORT;
                }
            }
        }
        catch (Exception e){
            msgCtxt.setVariable(varName("error"), e.getMessage());
            msgCtxt.setVariable(varName("stacktrace"), getStackTraceAsString(e));
            return ExecutionResult.ABORT;
        }
        return ExecutionResult.SUCCESS;
    }

    private static String getStackTraceAsString(Throwable t) {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        t.printStackTrace(pw);
        return sw.toString();
    }

    public static class HexEncoder {
        private static String byteToHex(byte num) {
            char[] hexDigits = new char[2];
            hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
            hexDigits[1] = Character.forDigit((num & 0xF), 16);
            return new String(hexDigits);
        }
        public static String encodeToString(byte[] byteArray) {
            StringBuffer hexStringBuffer = new StringBuffer();
            for (int i = 0; i < byteArray.length; i++) {
                hexStringBuffer.append(byteToHex(byteArray[i]));
            }
            return hexStringBuffer.toString();
        }
    }
}
