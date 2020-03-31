package com.google.apigee.callout.httpsignature;

public class SigGenerationResult {
    public Integer created;
    public Integer expires;
    public String headers;
    public String algorithm;
    public String signingBase;
    public String computedSignature;

    public String getSignatureHeader(String keyId) {
        String s = String.format("Signature keyId=\"%s\", algorithm=\"%s\", headers=\"%s\"",
                             keyId,
                             algorithm,
                             headers);
        if (created!=null) {
            s+= String.format(", created=%d", created);
        }
        if (expires!=null) {
            s+= String.format(", expires=%d", expires);
        }
        return s + String.format(", signature=\"%s\"", computedSignature);
    }
}
