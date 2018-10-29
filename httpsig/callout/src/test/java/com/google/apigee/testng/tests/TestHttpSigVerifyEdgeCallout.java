package com.google.apigee.testng.tests;

import java.util.HashMap;
import java.util.Map;

import org.testng.Assert;
import org.testng.annotations.Test;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.BeforeTest;

import mockit.Mock;
import mockit.MockUp;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.message.MessageContext;
import com.apigee.flow.execution.ExecutionResult;

import com.google.apigee.testng.support.NotImplementedException;
import com.google.apigee.callout.httpsignature.SignatureVerifierCallout;


public class TestHttpSigVerifyEdgeCallout {

    static {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    MessageContext msgCtxt;
    ExecutionContext exeCtxt;

    @BeforeTest()
    public void testSetup1() {

        msgCtxt = new MockUp<MessageContext>() {
            private Map variables;
            public void $init() {
                variables = new HashMap();
            }

            @Mock()
            public <T> T getVariable(final String name){
                if (variables == null) {
                    variables = new HashMap();
                }
                return (T) variables.get(name);
            }

            @Mock()
            public boolean setVariable(final String name, final Object value) {
                if (variables == null) {
                    variables = new HashMap();
                }
                variables.put(name, value);
                return true;
            }

            @Mock()
            public boolean removeVariable(final String name) {
                if (variables == null) {
                    variables = new HashMap();
                }
                if (variables.containsKey(name)) {
                    variables.remove(name);
                }
                return true;
            }

        }.getMockInstance();

        exeCtxt = new MockUp<ExecutionContext>(){ }.getMockInstance();
    }

    private static final String rsaKey1 = "-----BEGIN PUBLIC KEY-----\n"+
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXqRoSCsxL5VmVSpIDgt\n"+
"DAefUlS7G9rENta8SnW/cM19adBSFIFh5lT8LCcq7aw2Noyxdo/TchFubbGNfP+n\n"+
"FEVN+NU+noCDHUyl5FQBHFRIhWbk4etyJ49dqL8z01k0FPjeSiNNSxRVzpWgL221\n"+
"M/y0Im7v8DuKT89v161DcEdjbJ50jjM3I/kWBJawDlcD62yNMogx9cdHXUwgRm/V\n"+
"2XfYqdARxLKo384ONT8ZpUw8oF83S8tmhCXcOIdmY+AQxpYQoH/rAAdNe77IUXRp\n"+
"WqPUZvgzt9utZrhP7agaAKfg+Zc0PSJz4sfw3e2mwVfeW/bJvgeT+7jOn9NahIcw\n"+
"EwIDAQAB\n"+
        "-----END PUBLIC KEY-----\n";

        private static final String rsaKey2 =
"-----BEGIN PUBLIC KEY-----\n"+
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9htfJRKA3EEbvmvrqKON\n"+
"CGSDHYH3bJffNeca1sqvSN8uA2r16qabG5n21kvOZuzYr6gsK1Qpi870vELbir00\n"+
"xybyXTJKDjXsSTO+hSVa+bmr8V+ncAJr8ZkyWjPDYufGAsXqbLbUVWAbtiyCbgdA\n"+
"YBktWwXthQdz867l1ow21ZgR+vwzSDAAg8rK6PGIxqZ+7iVIUMW9eGJpr5vSdRXX\n"+
"Oushgcr84EBs7TH+0Pzw+rV2PRjD9gpyFvX/JMzx3UaJNscPEdne9wtuolk6VJpS\n"+
"KPTKTaXinS0grYvSUeY8+qmli20btNiaJ2La+giYAuPMiL99iStmlj+pTgnuVY65\n"+
"JQIDAQAB\n"+
            "-----END PUBLIC KEY-----\n";



    @Test()
    public void test1_Hmac_GoodSig_Property() {

        // set up
        Map properties = new HashMap();
        properties.put("fullsignature", "keyId=\"test1_Hmac_GoodSig_Property\",algorithm=\"hmac-sha256\",headers=\"date\",signature=\"Suk6A0tJCR1FHRemruL2NtyaGz54sCn5ow1suRhe54E=\"");
        properties.put("algorithm", "hmac-sha256");
        properties.put("headers", "date");
        properties.put("secret-key", "secret123");
        properties.put("maxtimeskew","-1");

        msgCtxt.setVariable("request.header.date", "Tue, 20 Oct 2015 16:55:05 PDT");
        SignatureVerifierCallout callout = new SignatureVerifierCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String error = msgCtxt.getVariable("httpsig_error");
        boolean isValid = msgCtxt.getVariable("httpsig_isValid");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(error, null);
        Assert.assertEquals(isValid, true);
    }

    @Test()
    public void test2_Hmac_WrongKey() {

        // set up
        Map properties = new HashMap();
        properties.put("fullsignature", "keyId=\"test2_Hmac_WrongKey\",algorithm=\"hmac-sha256\",headers=\"date\",signature=\"Suk6A0tJCR1FHRemruL2NtyaGz54sCn5ow1suRhe54E=\"");
        properties.put("algorithm", "hmac-sha256");
        properties.put("headers", "date");
        properties.put("secret-key", "secret1234");
        properties.put("maxtimeskew","-1");

        msgCtxt.setVariable("request.header.date", "Tue, 20 Oct 2015 16:55:05 PDT");
        SignatureVerifierCallout callout = new SignatureVerifierCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String error = msgCtxt.getVariable("httpsig_error");
        boolean isValid = msgCtxt.getVariable("httpsig_isValid");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(error, null);
        Assert.assertEquals(isValid, false);
    }

    @Test()
    public void test3_Hmac_WrongTime() {

        // set up
        Map properties = new HashMap();
        properties.put("fullsignature", "keyId=\"test3_Hmac_WrongTime\",algorithm=\"hmac-sha256\",headers=\"date\",signature=\"Suk6A0tJCR1FHRemruL2NtyaGz54sCn5ow1suRhe54E=\"");
        properties.put("algorithm", "hmac-sha256");
        properties.put("headers", "date");
        properties.put("secret-key", "secret123");
        properties.put("maxtimeskew","-1");

        msgCtxt.setVariable("request.header.date", "Tue, 20 Oct 2015 17:15:50 PDT");
        SignatureVerifierCallout callout = new SignatureVerifierCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String error = msgCtxt.getVariable("httpsig_error");
        boolean isValid = msgCtxt.getVariable("httpsig_isValid");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(error, null);
        Assert.assertEquals(isValid, false);
    }


    @Test()
    public void test4_Fail_AlgorithmMismatch() {

        // set up
        Map properties = new HashMap();
        properties.put("fullsignature", "keyId=\"test4_Fail_AlgorithmMismatch\",algorithm=\"rsa-sha256\",headers=\"(request-target) nonce date\",signature=\"udvCIHZAafyK+szbOI/KkLxeIihexHpHpvMrwbeoErI=\"");
        properties.put("algorithm", "hmac-sha256");
        properties.put("headers", "date");
        properties.put("maxtimeskew","-1");

        SignatureVerifierCallout callout = new SignatureVerifierCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String error = msgCtxt.getVariable("httpsig_error");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.ABORT);
        Assert.assertEquals(error, "algorithm used in signature (rsa-sha256) is not as required (hmac-sha256)");
    }


    @Test()
    public void rsa_WithSecretKey() {

        // set up
        Map properties = new HashMap();
        properties.put("fullsignature", "keyId=\"RSA_WithSecretKey\",algorithm=\"rsa-sha256\",headers=\"date\",signature=\"Suk6A0tJCR1FHRemruL2NtyaGz54sCn5ow1suRhe54E=\"");
        properties.put("algorithm", "rsa-sha256");
        properties.put("headers", "date");
        properties.put("secret-key", "secret123");
        properties.put("maxtimeskew","-1");

        msgCtxt.setVariable("request.header.date", "Tue, 20 Oct 2015 16:55:05 PDT");
        SignatureVerifierCallout callout = new SignatureVerifierCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String error = msgCtxt.getVariable("httpsig_error");
        boolean isValid = msgCtxt.getVariable("httpsig_isValid");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.ABORT);
        Assert.assertEquals(error, "must specify pemfile or public-key or certificate when algorithm is RS*");
        Assert.assertEquals(isValid, false);
    }

    @Test()
    public void rsa_IncorrectSignatureLength() {

        // set up
        Map properties = new HashMap();
        properties.put("fullsignature", "keyId=\"RSA_WithSecretKey\",algorithm=\"rsa-sha256\",headers=\"date\",signature=\"Suk6A0tJCR1FHRemruL2NtyaGz54sCn5ow1suRhe54E=\"");
        properties.put("algorithm", "rsa-sha256");
        properties.put("headers", "date");
        properties.put("public-key", rsaKey1);
        properties.put("maxtimeskew","-1");

        msgCtxt.setVariable("request.header.date", "Tue, 20 Oct 2015 16:55:05 PDT");
        SignatureVerifierCallout callout = new SignatureVerifierCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String error = msgCtxt.getVariable("httpsig_error");
        boolean isValid = msgCtxt.getVariable("httpsig_isValid");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.ABORT);
        Assert.assertEquals(error, "Signature length not correct: got 32 but was expecting 256");
        Assert.assertEquals(isValid, false);
    }


    @Test()
    public void rsa_GoodSig() {

        // set up
        Map properties = new HashMap();
        properties.put("fullsignature", "keyId=\"rsa_GoodSig\",algorithm=\"rsa-sha256\",headers=\"(request-target) date user-agent\",signature=\"gpgQqcxx8EB+NfDe7xiwYphEkfCSd1LdWWRTHYvtO89PmnI20ng4SX8nGlGbSdWvnuZO4IbKDLjXIs/ykwBqyAuS7poEiOgqQiV7ma+46WQUsylrliU4ldNqf3NsHDAEnVt139olVujvhTd0jZxIF99LUGrLVkbAGC3VnguoAQoXtq4G+Nh1fvB5Wkm5IIFeyjbZnbIAZri6fwvn+25VjAUkuhtJz71OnvtZm7PQCl+onOpKZC/0rCd+8cg5PNRC6MeDjV0PsT8M1TgcrdHdO2eamM5kyQfch0ICOC2gRKYZ1qAR7lxrvyJPDkJ2XvI+FqzVL8ao9zFKE59q543z0w==\"");

        properties.put("algorithm", "rsa-sha256");
        properties.put("headers", "date");
        properties.put("public-key", rsaKey2);
        properties.put("maxtimeskew","-1");

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



    // @Test()
    // public void test1_NoKey() {
    //
    //     // set up
    //     Map m = new HashMap();
    //     m.put("string-to-sign", "The quick brown fox...");
    //
    //     HmacCreatorCallout callout = new HmacCreatorCallout(m);
    //     ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
    //
    //     // retrieve output
    //     String error = msgCtxt.getVariable("hmac.error");
    //
    //     // check result and output
    //     Assert.assertEquals(result, ExecutionResult.ABORT);
    //     Assert.assertEquals(error, "key is not specified or is empty.");
    // }
    //
    // @Test()
    // public void test2_ValidConfig() {
    //
    //     // set up
    //     Map m = new HashMap();
    //     m.put("string-to-sign", "The quick brown fox...");
    //     m.put("key", "secret123");
    //     m.put("debug", "true");
    //
    //     // run it
    //     ExecutionResult result = new HmacCreatorCallout(m).execute(msgCtxt, exeCtxt);
    //
    //     // retrieve output
    //     String alg = msgCtxt.getVariable("hmac.javaizedAlg");
    //     //System.out.println("algorithm: " + alg);
    //     String error = msgCtxt.getVariable("hmac.error");
    //     //System.out.println("error: " + error);
    //     String key = msgCtxt.getVariable("hmac.key");
    //     //System.out.println("key: " + key);
    //     String hex = msgCtxt.getVariable("hmac.signature.hex");
    //     //System.out.println("hex: " + hex);
    //     String b64 = msgCtxt.getVariable("hmac.signature.b64");
    //     //System.out.println("b64: " + b64);
    //
    //     // check result and output
    //     Assert.assertEquals(result, ExecutionResult.SUCCESS);
    //     Assert.assertEquals(alg, "HmacSHA256");
    //     Assert.assertEquals(error, null);
    //     Assert.assertEquals(key, "secret123");
    //     Assert.assertEquals(b64, "5tC369Qn1HqQ0IbiCpU6DOwHPDTMdFI/SuIAXrIdjj0=");
    // }
    //
    //
    // @Test()
    // public void test3_KnownOutcome() {
    //     Map m = new HashMap();
    //     m.put("string-to-sign", "testing123");
    //     m.put("key", "hello");
    //     m.put("algorithm", "SHA-1");
    //     m.put("debug", "true");
    //
    //     ExecutionResult result = new HmacCreatorCallout(m).execute(msgCtxt, exeCtxt);
    //
    //     // retrieve output
    //     String alg = msgCtxt.getVariable("hmac.alg");
    //     String error = msgCtxt.getVariable("hmac.error");
    //     String hex = msgCtxt.getVariable("hmac.signature.hex");
    //
    //     // check result and output
    //     Assert.assertEquals(result, ExecutionResult.SUCCESS);
    //     Assert.assertEquals(alg, "SHA-1");
    //     Assert.assertEquals(error, null);
    //     Assert.assertEquals(hex.toLowerCase(), "ac2c2e614882ce7158f69b7e3b12114465945d01");
    // }
    //
    // @Test()
    // public void test4_KnownOutcome_MD5() {
    //     // set up
    //     Map m = new HashMap();
    //     m.put("string-to-sign", "testing123");
    //     m.put("key", "hello");
    //     m.put("algorithm", "MD-5");
    //     m.put("debug", "true");
    //
    //     // run it
    //     ExecutionResult result = new HmacCreatorCallout(m).execute(msgCtxt, exeCtxt);
    //
    //     // retrieve output
    //     String alg = msgCtxt.getVariable("hmac.javaizedAlg");
    //     //System.out.println("algorithm: " + alg);
    //     String error = msgCtxt.getVariable("hmac.error");
    //     //System.out.println("error: " + error);
    //     String hex = msgCtxt.getVariable("hmac.signature.hex");
    //     //System.out.println("hex: " + hex);
    //
    //     // check result and output
    //     Assert.assertEquals(result, ExecutionResult.SUCCESS);
    //     Assert.assertEquals(error, null);
    //     Assert.assertEquals(alg, "HmacMD5");
    //     Assert.assertEquals(hex.toLowerCase(), "1fcd2cdb3005f4d9baef9f3957cd2d1f");
    // }
    //
    // @Test()
    // public void VerifyHmac1() {
    //     Map m = new HashMap();
    //     m.put("string-to-sign", "The quick brown fox...");
    //     m.put("key", "secret123");
    //     m.put("algorithm", "SHA-256");
    //     m.put("hmac-base64", "5tC369Qn1HqQ0IbiCpU6DOwHPDTMdFI/SuIAXrIdjj0=");
    //     m.put("debug", "true");
    //
    //     ExecutionResult result = new HmacCreatorCallout(m).execute(msgCtxt, exeCtxt);
    //
    //     // retrieve output
    //     String error = msgCtxt.getVariable("hmac.error");
    //
    //     // check result and output
    //     Assert.assertEquals(result, ExecutionResult.SUCCESS);
    //     Assert.assertEquals(error, null);
    // }
    //
    // @Test()
    // public void VerifyHmacFailure1() {
    //     Map m = new HashMap();
    //     m.put("string-to-sign", "The quick brown fox..!");
    //     m.put("key", "secret123");
    //     m.put("algorithm", "SHA-256");
    //     m.put("hmac-base64", "5tC369Qn1HqQ0IbiCpU6DOwHPDTMdFI/SuIAXrIdjj0=");
    //     m.put("debug", "true");
    //
    //     ExecutionResult result = new HmacCreatorCallout(m).execute(msgCtxt, exeCtxt);
    //
    //     // retrieve output
    //     String error = msgCtxt.getVariable("hmac.error");
    //
    //     // check result and output
    //     Assert.assertEquals(result, ExecutionResult.ABORT);
    //     Assert.assertEquals(error, "HMAC does not verify");
    // }


}
