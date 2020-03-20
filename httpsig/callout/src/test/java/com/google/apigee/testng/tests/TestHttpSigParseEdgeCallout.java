package com.google.apigee.testng.tests;

import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;

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

import com.google.apigee.callout.httpsignature.SignatureParserCallout;

public class TestHttpSigParseEdgeCallout {

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
                T value = (T) variables.get(name);
                System.out.printf("getVariable(%s) => %s\n", name, (value==null)?"-null-": value.toString());
                return value;
            }

            @Mock()
            public boolean setVariable(final String name, final Object value) {
                if (variables == null) {
                    variables = new HashMap();
                }
                System.out.printf("setVariable(%s) <= %s\n", name, (value==null)?"-null-": value.toString());
                variables.put(name, value);
                return true;
            }

            @Mock()
            public boolean removeVariable(final String name) {
                if (variables == null) {
                    variables = new HashMap();
                }
                System.out.printf("removeVariable(%s)\n", name);
                if (variables.containsKey(name)) {
                    variables.remove(name);
                }
                return true;
            }

        }.getMockInstance();

        exeCtxt = new MockUp<ExecutionContext>(){ }.getMockInstance();
    }


    @Test()
    public void test1_BadSig_Property() {
        Map m = new HashMap();
        m.put("fullsignature", "The quick brown fox...");

        SignatureParserCallout callout = new SignatureParserCallout(m);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String error = msgCtxt.getVariable("httpsig_error");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.ABORT);
        Assert.assertEquals(error, "the signature is malformed (The quick brown fox...)");
    }

    @Test()
    public void test2_GoodSig_Property() {
        Map properties = new HashMap();
        properties.put("fullsignature", "keyId=\"test2_GoodSig_Property\",algorithm=\"hmac-sha256\",headers=\"(request-target) date\",signature=\"udvCIHZAafyK+szbOI/KkLxeIihexHpHpvMrwbeoErI=\"");
        properties.put("algorithm", "hmac-sha256");
        properties.put("headers", "date");
        properties.put("maxtimeskew","-1");

        // msgCtxt.setVariable("request.header.date", "Tue, 20 Oct 2015 16:55:05 PDT")
        SignatureParserCallout callout = new SignatureParserCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String error = msgCtxt.getVariable("httpsig_error");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(error, null);
    }

    @Test()
    public void test3_GoodSig_Header() {
        Map properties = new HashMap();
        properties.put("algorithm", "hmac-sha256");
        properties.put("headers", "date");
        properties.put("debug", "true");
        properties.put("maxtimeskew","-1");

        // msgCtxt.setVariable("request.header.date", "Tue, 20 Oct 2015 16:55:05 PDT")
        ArrayList list = new ArrayList<String>();
        list.add("keyId=\"test3_GoodSig_Header\"");
        list.add("algorithm=\"hmac-sha256\"");
        list.add("headers=\"(request-target) date\"");
        list.add("signature=\"udvCIHZAafyK+szbOI/KkLxeIihexHpHpvMrwbeoErI=\"");
        msgCtxt.setVariable("request.header.signature.values", list);

        SignatureParserCallout callout = new SignatureParserCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String error = msgCtxt.getVariable("httpsig_error");

        // check result and output
        //Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(error, null, "error");
    }

    @Test()
    public void denis_20200320() {
        Map properties = new HashMap();
        properties.put("algorithm", "rsa-sha256");
        properties.put("headers", "user");
        properties.put("debug", "true");

        // msgCtxt.setVariable("request.header.date", "Tue, 20 Oct 2015 16:55:05 PDT")
        ArrayList list = new ArrayList<String>();
        list.add("keyId=\"denis_20200320\"");
        list.add("algorithm=\"rsa-sha256\"");
        list.add("headers=\"user\"");
        list.add("signature=\"DH7DFavH1j76Hk4oiqTW1hAcmfLHq/1NcFZbgzvtJuLyber7mnih0jBRbvqe7iI34pi6PNZhXLnzvSm6y3e966n4q/yVWwA7Eb17hSkcwcFEiZvzThpM2zjWxRe5fdY3DvjGolBFQJZryx2eF2XzhVS0SowbyWJ/V+bf2GXYF5WvY/3NZczH6X6k58BAdv1Bl7CY0N0LrMbKdCWBDjFCU891B0RzgqaK9XX0z839Lscj6zsTkUh+PzGYvdrLi0CyI36pGUSEzhT/lY2StHR6MFimnXiOc1Y1U0rHnpI09659WDPLPwcCOenQgW4LxsbwQJQ795yJhiGRrRphfqeycg==\"");
        msgCtxt.setVariable("request.header.signature.values", list);

        SignatureParserCallout callout = new SignatureParserCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String error = msgCtxt.getVariable("httpsig_error");

        // check result and output
        //Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(error, null, "error");
    }


    @Test()
    public void test4_BadHeader_Algorithm() {
        Map properties = new HashMap();
        properties.put("fullsignature", "keyId=\"test4_BadHeader_Algorithm\",algorithm=\"icecream\",headers=\"(request-target) date\",signature=\"udvCIHZAafyK+szbOI/KkLxeIihexHpHpvMrwbeoErI=\"");
        properties.put("algorithm", "hmac-sha256");
        properties.put("headers", "date");
        properties.put("maxtimeskew","-1");

        SignatureParserCallout callout = new SignatureParserCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String error = msgCtxt.getVariable("httpsig_error");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.ABORT);
        Assert.assertEquals(error, "unsupported algorithm: icecream");
    }

    @Test()
    public void test5_RSA_GoodHeader() {
        Map properties = new HashMap();
        properties.put("fullsignature", "keyId=\"test5_RSA_GoodHeader\",algorithm=\"rsa-sha256\",headers=\"(request-target) nonce date\",signature=\"udvCIHZAafyK+szbOI/KkLxeIihexHpHpvMrwbeoErI=\"");
        properties.put("algorithm", "hmac-sha256");
        properties.put("headers", "date");
        properties.put("maxtimeskew","-1");

        SignatureParserCallout callout = new SignatureParserCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String error = msgCtxt.getVariable("httpsig_error");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(error, null);
    }

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
