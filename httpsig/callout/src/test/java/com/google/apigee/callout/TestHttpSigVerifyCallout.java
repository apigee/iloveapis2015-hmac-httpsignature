package com.google.apigee.callout;

import com.apigee.flow.execution.ExecutionResult;
import com.google.apigee.callout.httpsignature.SignatureVerifierCallout;
import java.util.HashMap;
import java.util.Map;
import org.testng.Assert;
import org.testng.annotations.Test;

public class TestHttpSigVerifyCallout extends CalloutTestBase {

  private static final String rsaKey1 =
      "-----BEGIN PUBLIC KEY-----\n"
          + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXqRoSCsxL5VmVSpIDgt\n"
          + "DAefUlS7G9rENta8SnW/cM19adBSFIFh5lT8LCcq7aw2Noyxdo/TchFubbGNfP+n\n"
          + "FEVN+NU+noCDHUyl5FQBHFRIhWbk4etyJ49dqL8z01k0FPjeSiNNSxRVzpWgL221\n"
          + "M/y0Im7v8DuKT89v161DcEdjbJ50jjM3I/kWBJawDlcD62yNMogx9cdHXUwgRm/V\n"
          + "2XfYqdARxLKo384ONT8ZpUw8oF83S8tmhCXcOIdmY+AQxpYQoH/rAAdNe77IUXRp\n"
          + "WqPUZvgzt9utZrhP7agaAKfg+Zc0PSJz4sfw3e2mwVfeW/bJvgeT+7jOn9NahIcw\n"
          + "EwIDAQAB\n"
          + "-----END PUBLIC KEY-----\n";

  private static final String rsaKey2 =
      "-----BEGIN PUBLIC KEY-----\n"
          + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9htfJRKA3EEbvmvrqKON\n"
          + "CGSDHYH3bJffNeca1sqvSN8uA2r16qabG5n21kvOZuzYr6gsK1Qpi870vELbir00\n"
          + "xybyXTJKDjXsSTO+hSVa+bmr8V+ncAJr8ZkyWjPDYufGAsXqbLbUVWAbtiyCbgdA\n"
          + "YBktWwXthQdz867l1ow21ZgR+vwzSDAAg8rK6PGIxqZ+7iVIUMW9eGJpr5vSdRXX\n"
          + "Oushgcr84EBs7TH+0Pzw+rV2PRjD9gpyFvX/JMzx3UaJNscPEdne9wtuolk6VJpS\n"
          + "KPTKTaXinS0grYvSUeY8+qmli20btNiaJ2La+giYAuPMiL99iStmlj+pTgnuVY65\n"
          + "JQIDAQAB\n"
          + "-----END PUBLIC KEY-----\n";

  @Test()
  public void hmac_GoodSig_Property() {
    Map properties = new HashMap();
    properties.put(
        "fullsignature",
        "keyId=\"hmac_GoodSig_Property\",algorithm=\"hmac-sha256\",headers=\"date\",signature=\"Suk6A0tJCR1FHRemruL2NtyaGz54sCn5ow1suRhe54E=\"");
    properties.put("algorithm", "hmac-sha256");
    properties.put("headers", "date");
    properties.put("secret-key", "secret123");
    properties.put("maxtimeskew", "-1");

    msgCtxt.setVariable("request.header.date", "Tue, 20 Oct 2015 16:55:05 PDT");
    SignatureVerifierCallout callout = new SignatureVerifierCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    String error = msgCtxt.getVariable("httpsig_error");
    boolean isValid = msgCtxt.getVariable("httpsig_isValid");

    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    Assert.assertEquals(error, null);
    Assert.assertEquals(isValid, true);
  }

  @Test()
  public void hmac_WrongKey() {
    Map properties = new HashMap();
    properties.put(
        "fullsignature",
        "keyId=\"hmac_WrongKey\",algorithm=\"hmac-sha256\",headers=\"date\",signature=\"Suk6A0tJCR1FHRemruL2NtyaGz54sCn5ow1suRhe54E=\"");
    properties.put("algorithm", "hmac-sha256");
    properties.put("headers", "date");
    properties.put("secret-key", "secret1234");
    properties.put("maxtimeskew", "-1");

    msgCtxt.setVariable("request.header.date", "Tue, 20 Oct 2015 16:55:05 PDT");
    SignatureVerifierCallout callout = new SignatureVerifierCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    String error = msgCtxt.getVariable("httpsig_error");
    boolean isValid = msgCtxt.getVariable("httpsig_isValid");

    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    Assert.assertEquals(error, null);
    Assert.assertEquals(isValid, false);
  }

  @Test()
  public void hmac_WrongDate() {
    Map properties = new HashMap();
    properties.put(
        "fullsignature",
        "keyId=\"hmac_WrongDate\",algorithm=\"hmac-sha256\",headers=\"date\",signature=\"Suk6A0tJCR1FHRemruL2NtyaGz54sCn5ow1suRhe54E=\"");
    properties.put("algorithm", "hmac-sha256");
    properties.put("headers", "date");
    properties.put("secret-key", "secret123");
    properties.put("maxtimeskew", "-1");

    msgCtxt.setVariable("request.header.date", "Tue, 20 Oct 2015 17:15:50 PDT");
    SignatureVerifierCallout callout = new SignatureVerifierCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    String error = msgCtxt.getVariable("httpsig_error");
    boolean isValid = msgCtxt.getVariable("httpsig_isValid");

    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    Assert.assertEquals(error, null);
    Assert.assertEquals(isValid, false);
  }

  @Test()
  public void algorithmMismatch() {
    Map properties = new HashMap();
    properties.put(
        "fullsignature",
        "keyId=\"algorithmMismatch\",algorithm=\"rsa-sha256\",headers=\"(request-target) nonce date\",signature=\"udvCIHZAafyK+szbOI/KkLxeIihexHpHpvMrwbeoErI=\"");
    properties.put("algorithm", "hmac-sha256");
    properties.put("headers", "date");
    properties.put("maxtimeskew", "-1");

    SignatureVerifierCallout callout = new SignatureVerifierCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    String error = msgCtxt.getVariable("httpsig_error");

    Assert.assertEquals(result, ExecutionResult.ABORT);
    Assert.assertEquals(
        error, "algorithm used in signature (rsa-sha256) is not as required (hmac-sha256)");
  }

  @Test()
  public void rsa_WithSecretKey() {
    Map properties = new HashMap();
    properties.put(
        "fullsignature",
        "keyId=\"RSA_WithSecretKey\",algorithm=\"rsa-sha256\",headers=\"date\",signature=\"Suk6A0tJCR1FHRemruL2NtyaGz54sCn5ow1suRhe54E=\"");
    properties.put("algorithm", "rsa-sha256");
    properties.put("headers", "date");
    properties.put("secret-key", "secret123");
    properties.put("maxtimeskew", "-1");

    msgCtxt.setVariable("request.header.date", "Tue, 20 Oct 2015 16:55:05 PDT");
    SignatureVerifierCallout callout = new SignatureVerifierCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    String error = msgCtxt.getVariable("httpsig_error");
    boolean isValid = msgCtxt.getVariable("httpsig_isValid");

    Assert.assertEquals(result, ExecutionResult.ABORT);
    Assert.assertEquals(error, "no source for public-key");
    Assert.assertEquals(isValid, false);
  }

  @Test()
  public void rsa_IncorrectSignatureLength() {
    Map properties = new HashMap();
    properties.put(
        "fullsignature",
        "keyId=\"rsa_IncorrectSignatureLength\",algorithm=\"rsa-sha256\",headers=\"date\",signature=\"Suk6A0tJCR1FHRemruL2NtyaGz54sCn5ow1suRhe54E=\"");
    properties.put("algorithm", "rsa-sha256");
    properties.put("headers", "date");
    properties.put("public-key", rsaKey1);
    properties.put("maxtimeskew", "-1");

    msgCtxt.setVariable("request.header.date", "Tue, 20 Oct 2015 16:55:05 PDT");
    SignatureVerifierCallout callout = new SignatureVerifierCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    String error = msgCtxt.getVariable("httpsig_error");
    boolean isValid = msgCtxt.getVariable("httpsig_isValid");

    Assert.assertEquals(result, ExecutionResult.ABORT);
    Assert.assertEquals(error, "Signature length not correct: got 32 but was expecting 256");
    Assert.assertEquals(isValid, false);
  }

  @Test()
  public void rsa_GoodSig() {
    Map properties = new HashMap();
    properties.put(
        "fullsignature",
        "keyId=\"rsa_GoodSig\",algorithm=\"rsa-sha256\",headers=\"(request-target) date user-agent\",signature=\"gpgQqcxx8EB+NfDe7xiwYphEkfCSd1LdWWRTHYvtO89PmnI20ng4SX8nGlGbSdWvnuZO4IbKDLjXIs/ykwBqyAuS7poEiOgqQiV7ma+46WQUsylrliU4ldNqf3NsHDAEnVt139olVujvhTd0jZxIF99LUGrLVkbAGC3VnguoAQoXtq4G+Nh1fvB5Wkm5IIFeyjbZnbIAZri6fwvn+25VjAUkuhtJz71OnvtZm7PQCl+onOpKZC/0rCd+8cg5PNRC6MeDjV0PsT8M1TgcrdHdO2eamM5kyQfch0ICOC2gRKYZ1qAR7lxrvyJPDkJ2XvI+FqzVL8ao9zFKE59q543z0w==\"");

    properties.put("algorithm", "rsa-sha256");
    properties.put("headers", "date");
    properties.put("public-key", rsaKey2);
    properties.put("maxtimeskew", "-1");

    msgCtxt.setVariable("request.header.date", "Mon, 29 Oct 2018 19:29:18 GMT");
    msgCtxt.setVariable("request.header.user-agent", "nodejs httpSigClient.js");
    msgCtxt.setVariable("proxy.url", "/httpsig/rsa-t1?how=areyou");
    msgCtxt.setVariable("request.verb", "GET");
    SignatureVerifierCallout callout = new SignatureVerifierCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // retrieve output
    String signingBase = msgCtxt.getVariable("httpsig_signingBase");
    System.out.printf("SigningBase: %s\n", signingBase);

    String error = msgCtxt.getVariable("httpsig_error");
    boolean isValid = msgCtxt.getVariable("httpsig_isValid");

    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    Assert.assertEquals(error, null);
    Assert.assertEquals(isValid, true);
  }

  @Test()
  public void hs2019_rsa_Good() {
    Map properties = new HashMap();
    properties.put(
        "fullsignature",
        "Signature keyId=\"hs2019_rsa_Good\", algorithm=\"hs2019\", headers=\"x-request-id tpp-redirect-uri digest psu-id\", signature=\"TgbIVw/ON8mTvd7+R5nbcYPl62CwJaHDjNOWfw+AFLbpJANmgR3+J88x8XwI8Q0gbc8mlmosfC7Oyu9A6vUTQpKosU7VglwC4SlVtMhbqM3xFw+yeQstKIjikAvy0ZvSaFOCWNubbRgJTq6fQCjNjqrMchKesMHAaTGRE4BVHUAXe3QAGDiVh3B7hLb9tIN83WZoZpX2lH+fQS3I3uHfCRsZixSkjH9t+hNGz858DL9heobs7s1wc88MfRUfnxUpXZlcZnH3ZfOI8/1xYBvOkUCla7Z0Tiqy+tfUaHp3VMTC+theBTVvukCFVakaMOY/IHX2S42uHQWI7UTBP2XpuQ==\"");

    properties.put("algorithm", "hs2019");
    properties.put("hs2019-algorithm", "rsa");
    properties.put("headers", "x-request-id psu-id digest");
    properties.put("public-key", rsaKey1);
    properties.put("debug", "true");

    msgCtxt.setVariable("request.header.psu-id", "1337");
    msgCtxt.setVariable("request.header.tpp-redirect-uri", "https://www.sometpp.com/redirect/");
    msgCtxt.setVariable(
        "request.header.digest", "SHA-256=TGGHcPGLechhcNo4gndoKUvCBhWaQOPgtoVDIpxc6J4=");
    msgCtxt.setVariable("request.header.x-request-id", "00000000-0000-0000-0000-000000000004");

    SignatureVerifierCallout callout = new SignatureVerifierCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    String signingBase = msgCtxt.getVariable("httpsig_signingBase");
    System.out.printf("SigningBase: %s\n", signingBase);

    String error = msgCtxt.getVariable("httpsig_error");
    boolean isValid = msgCtxt.getVariable("httpsig_isValid");

    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    Assert.assertEquals(error, null);
    Assert.assertEquals(isValid, true);
  }

  @Test()
  public void hs2019_hmac_Good() {
    Map properties = new HashMap();
    properties.put(
        "fullsignature",
        "Signature keyId=\"hs2019_hmac_Good\", algorithm=\"hs2019\", headers=\"x-request-id tpp-redirect-uri digest psu-id\", signature=\"jr9m69VJsQQJWrTyzaWiXrWZeg498e9PAO+yxiI9L2niaJXocMGTYqAZbde6B7v7Jd532TXgKHXAFZdXIHPgsQ==\"");

    properties.put("algorithm", "hs2019");
    properties.put("hs2019-algorithm", "hmac");
    properties.put("headers", "x-request-id psu-id digest tpp-redirect-uri");
    properties.put("secret-key", "Secret1234567890ABCDEFGHIJKLMNOP");
    properties.put("debug", "true");

    msgCtxt.setVariable("request.header.psu-id", "1337");
    msgCtxt.setVariable("request.header.tpp-redirect-uri", "https://www.sometpp.com/redirect/");
    msgCtxt.setVariable(
        "request.header.digest", "SHA-256=TGGHcPGLechhcNo4gndoKUvCBhWaQOPgtoVDIpxc6J4=");
    msgCtxt.setVariable("request.header.x-request-id", "00000000-0000-0000-0000-000000000004");

    SignatureVerifierCallout callout = new SignatureVerifierCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    String signingBase = msgCtxt.getVariable("httpsig_signingBase");
    System.out.printf("SigningBase: %s\n", signingBase);

    String error = msgCtxt.getVariable("httpsig_error");
    boolean isValid = msgCtxt.getVariable("httpsig_isValid");

    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    Assert.assertEquals(error, null);
    Assert.assertEquals(isValid, true);
  }

  @Test()
  public void hs2019_hmac_Created() {
    Map properties = new HashMap();
    properties.put(
        "fullsignature",
        "Signature keyId=\"hs2019_hmac_Created\", algorithm=\"hs2019\", headers=\"x-request-id created\", created=1585359103, signature=\"KpzrYXpfHYOWULE40i4MzwhjlsXdO0Sh7nP1sl6aDw2UKlnFdtXLyPdFyc/yc60c/sTy/L97uEDzjK+j6+1FXg==\"");

    properties.put("algorithm", "hs2019");
    properties.put("hs2019-algorithm", "hmac");
    properties.put("headers", "x-request-id");
    properties.put("secret-key", "Secret1234567890ABCDEFGHIJKLMNOP");
    properties.put("debug", "true");

    msgCtxt.setVariable("request.header.x-request-id", "00000000-0000-0000-0000-000000000004");

    SignatureVerifierCallout callout = new SignatureVerifierCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    String signingBase = msgCtxt.getVariable("httpsig_signingBase");
    System.out.printf("SigningBase: %s\n", signingBase);

    String error = msgCtxt.getVariable("httpsig_error");
    boolean isValid = msgCtxt.getVariable("httpsig_isValid");

    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    Assert.assertEquals(error, null);
    Assert.assertEquals(isValid, true);
  }

  @Test()
  public void hs2019_hmac_CreatedAndExpires() {
    Map properties = new HashMap();
    properties.put(
        "fullsignature",
        "Signature keyId=\"hs2019_hmac_CreatedAndExpires\", algorithm=\"hs2019\", headers=\"x-request-id created expires\", created=1585359627, expires=1585359927, signature=\"/UgploIox2L4oh9h4/SwMyeLpKx78/rLVay9GGzXPM06EZ68KAwUHQhc9p1Il7lSOO7l0nmPrMQdHjlQcMRbRA==\"");

    properties.put("algorithm", "hs2019");
    properties.put("hs2019-algorithm", "hmac");
    properties.put("headers", "x-request-id");
    properties.put("secret-key", "Secret1234567890ABCDEFGHIJKLMNOP");
    properties.put("debug", "true");

    msgCtxt.setVariable("request.header.x-request-id", "00000000-0000-0000-0000-000000000004");

    SignatureVerifierCallout callout = new SignatureVerifierCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
    String signingBase = msgCtxt.getVariable("httpsig_signingBase");
    System.out.printf("SigningBase: %s\n", signingBase);

    String error = msgCtxt.getVariable("httpsig_error");
    boolean isValid = msgCtxt.getVariable("httpsig_isValid");

    Assert.assertEquals(result, ExecutionResult.ABORT);
    Assert.assertEquals(error, "the signature has expired");
    Assert.assertEquals(isValid, false);
  }

  @Test()
  public void hs2019_hmac_CreatedAndExpires_IgnoreExpiry() {
    Map properties = new HashMap();
    properties.put(
        "fullsignature",
        "Signature keyId=\"hs2019_hmac_CreatedAndExpires_IgnoreExpiry\", algorithm=\"hs2019\", headers=\"x-request-id created expires\", created=1585359627, expires=1585359927, signature=\"/UgploIox2L4oh9h4/SwMyeLpKx78/rLVay9GGzXPM06EZ68KAwUHQhc9p1Il7lSOO7l0nmPrMQdHjlQcMRbRA==\"");

    properties.put("algorithm", "hs2019");
    properties.put("hs2019-algorithm", "hmac");
    properties.put("headers", "x-request-id");
    properties.put("maxtimeskew", "10000d"); // ~27 years from Friday, 27 March 2020, 19:06
    properties.put("secret-key", "Secret1234567890ABCDEFGHIJKLMNOP");
    properties.put("debug", "true");

    msgCtxt.setVariable("request.header.x-request-id", "00000000-0000-0000-0000-000000000004");

    SignatureVerifierCallout callout = new SignatureVerifierCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
    String signingBase = msgCtxt.getVariable("httpsig_signingBase");
    System.out.printf("SigningBase: %s\n", signingBase);

    String error = msgCtxt.getVariable("httpsig_error");
    boolean isValid = msgCtxt.getVariable("httpsig_isValid");

    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    Assert.assertEquals(error, null);
    Assert.assertEquals(isValid, true);
  }

  @Test()
  public void hmac_base64EncodedKey() {
    Map properties = new HashMap();
    properties.put(
        "fullsignature",
        "Signature keyId=\"hmac_base64EncodedKey\", algorithm=\"hmac-sha256\", headers=\"x-request-id\", signature=\"zLLFGuErvRxpMEOPv3WwPoktkUeHL8Apltb2f1WrrBs=\"");

    properties.put("algorithm", "hmac-sha256");
    properties.put("headers", "x-request-id");

    // this key is "Secret1234567890ABCDEFGHIJKLMNOP", encoded in base64
    properties.put("secret-key", "U2VjcmV0MTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1A=");
    properties.put("secret-key-encoding", "base64");
    properties.put("debug", "true");

    msgCtxt.setVariable("request.header.x-request-id", "00000000-0000-0000-0000-000000000004");

    SignatureVerifierCallout callout = new SignatureVerifierCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
    String signingBase = msgCtxt.getVariable("httpsig_signingBase");
    System.out.printf("SigningBase: %s\n", signingBase);

    String error = msgCtxt.getVariable("httpsig_error");
    boolean isValid = msgCtxt.getVariable("httpsig_isValid");

    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    Assert.assertEquals(error, null);
    Assert.assertEquals(isValid, true);
  }

  @Test()
  public void hmac_hexEncodedKey() {
    Map properties = new HashMap();
    properties.put(
        "fullsignature",
        "Signature keyId=\"hmac_base64EncodedKey\", algorithm=\"hmac-sha256\", headers=\"x-request-id\", signature=\"zLLFGuErvRxpMEOPv3WwPoktkUeHL8Apltb2f1WrrBs=\"");

    properties.put("algorithm", "hmac-sha256");
    properties.put("headers", "x-request-id");

    // this key is "Secret1234567890ABCDEFGHIJKLMNOP", encoded in base64
    properties.put(
        "secret-key", "536563726574313233343536373839304142434445464748494a4b4c4d4e4f50");
    properties.put("secret-key-encoding", "hex");
    properties.put("debug", "true");

    msgCtxt.setVariable("request.header.x-request-id", "00000000-0000-0000-0000-000000000004");

    SignatureVerifierCallout callout = new SignatureVerifierCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
    String signingBase = msgCtxt.getVariable("httpsig_signingBase");
    System.out.printf("SigningBase: %s\n", signingBase);

    String error = msgCtxt.getVariable("httpsig_error");
    boolean isValid = msgCtxt.getVariable("httpsig_isValid");

    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    Assert.assertEquals(error, null);
    Assert.assertEquals(isValid, true);
  }

  @Test()
  public void hmac_base16EncodedKey() {
    Map properties = new HashMap();
    properties.put(
        "fullsignature",
        "Signature keyId=\"hmac_base64EncodedKey\", algorithm=\"hmac-sha256\", headers=\"x-request-id\", signature=\"zLLFGuErvRxpMEOPv3WwPoktkUeHL8Apltb2f1WrrBs=\"");

    properties.put("algorithm", "hmac-sha256");
    properties.put("headers", "x-request-id");

    // this key is "Secret1234567890ABCDEFGHIJKLMNOP", encoded in base64
    properties.put(
        "secret-key", "536563726574313233343536373839304142434445464748494a4b4c4d4e4f50");
    properties.put("secret-key-encoding", "base16");
    properties.put("debug", "true");

    msgCtxt.setVariable("request.header.x-request-id", "00000000-0000-0000-0000-000000000004");

    SignatureVerifierCallout callout = new SignatureVerifierCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
    String signingBase = msgCtxt.getVariable("httpsig_signingBase");
    System.out.printf("SigningBase: %s\n", signingBase);

    String error = msgCtxt.getVariable("httpsig_error");
    boolean isValid = msgCtxt.getVariable("httpsig_isValid");

    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    Assert.assertEquals(error, null);
    Assert.assertEquals(isValid, true);
  }
}
