package com.apigee.testng.tests;

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

import com.apigee.testng.support.NotImplementedException;

import com.apigee.callout.hmac.HmacCreatorCallout;


public class TestHmacCallout {

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
                System.out.printf("getVariable(%s) => %s\n", name, (value==null)?"-null-":value.toString());
                return value;
            }

            @Mock()
            public boolean setVariable(final String name, final Object value) {
                if (variables == null) {
                    variables = new HashMap();
                }
                System.out.printf("setVariable(%s) <= %s\n", name, (value==null)?"-null-":value.toString());
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
    public void noKey() {

        // set up
        Map m = new HashMap();
        m.put("string-to-sign", "The quick brown fox...");

        HmacCreatorCallout callout = new HmacCreatorCallout(m);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String error = msgCtxt.getVariable("hmac.error");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.ABORT);
        Assert.assertEquals(error, "configuration error: secret-key is not specified or is empty.");
    }

    @Test()
    public void validConfig1() {

        // set up
        Map m = new HashMap();
        m.put("string-to-sign", "The quick brown fox...");
        m.put("key", "secret123");
        m.put("debug", "true");

        // run it
        ExecutionResult result = new HmacCreatorCallout(m).execute(msgCtxt, exeCtxt);

        // retrieve output
        String alg = msgCtxt.getVariable("hmac.javaizedAlg");
        //System.out.println("algorithm: " + alg);
        String error = msgCtxt.getVariable("hmac.error");
        //System.out.println("error: " + error);
        //String key = msgCtxt.getVariable("hmac.key");
        //System.out.println("key: " + key);
        String hex = msgCtxt.getVariable("hmac.signature.hex");
        //System.out.println("hex: " + hex);
        String b64 = msgCtxt.getVariable("hmac.signature.b64");
        //System.out.println("b64: " + b64);

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(alg, "HmacSHA256");
        Assert.assertEquals(error, null);
        //Assert.assertEquals(key, "secret123");
        Assert.assertEquals(b64, "5tC369Qn1HqQ0IbiCpU6DOwHPDTMdFI/SuIAXrIdjj0=");
    }

    @Test()
    public void validConfig2() {

        // set up
        Map m = new HashMap();
        m.put("string-to-sign", "abc");
        m.put("algorithm", "SHA-256");
        m.put("key", "Secret123");

        ExecutionResult result = new HmacCreatorCallout(m).execute(msgCtxt, exeCtxt);

        // retrieve output
        String error = msgCtxt.getVariable("hmac.error");
        String hex = msgCtxt.getVariable("hmac.signature.hex");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(error, null);
        Assert.assertEquals(hex, "a7938720fe5749d31076e6961360364c0cd271443f1b580779932c244293bc94");
    }

    @Test()
    public void secretKeyProperty() {

        // the secret-key property supercedes the "key" property
        // set up
        Map m = new HashMap();
        m.put("string-to-sign", "abc");
        m.put("algorithm", "SHA-256");
        m.put("secret-key", "Secret123");
        m.put("key", "wrongkey");

        ExecutionResult result = new HmacCreatorCallout(m).execute(msgCtxt, exeCtxt);

        // retrieve output
        String error = msgCtxt.getVariable("hmac.error");
        String hex = msgCtxt.getVariable("hmac.signature.hex");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(error, null);
        Assert.assertEquals(hex, "a7938720fe5749d31076e6961360364c0cd271443f1b580779932c244293bc94");
    }

    @Test()
    public void utf8EncodedKey() {

        Map m = new HashMap();
        m.put("string-to-sign", "abc");
        m.put("algorithm", "SHA-256");
        m.put("secret-key", "Secret123");
        m.put("secret-key-encoding", "utf-8"); // UTF-8 is the default

        ExecutionResult result = new HmacCreatorCallout(m).execute(msgCtxt, exeCtxt);

        // retrieve output
        String error = msgCtxt.getVariable("hmac.error");
        String hex = msgCtxt.getVariable("hmac.signature.hex");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(error, null);
        Assert.assertEquals(hex, "a7938720fe5749d31076e6961360364c0cd271443f1b580779932c244293bc94");
    }

    @Test()
    public void base16EncodedKey() {

        // set up
        Map m = new HashMap();
        m.put("string-to-sign", "abc");
        m.put("algorithm", "SHA-256");
        m.put("secret-key", "536563726574313233"); // Secret123 in base16
        m.put("secret-key-encoding", "base16");

        ExecutionResult result = new HmacCreatorCallout(m).execute(msgCtxt, exeCtxt);

        // retrieve output
        String error = msgCtxt.getVariable("hmac.error");
        String hex = msgCtxt.getVariable("hmac.signature.hex");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(error, null);
        Assert.assertEquals(hex, "a7938720fe5749d31076e6961360364c0cd271443f1b580779932c244293bc94");
    }

    @Test()
    public void base64EncodedKey() {

        // set up
        Map m = new HashMap();
        m.put("string-to-sign", "abc");
        m.put("algorithm", "SHA-256");
        m.put("secret-key", "p5OHIP5XSdMQduaWE2A2TAzScUQ/G1gHeZMsJEKTvJQ=");
        m.put("secret-key-encoding", "base64");

        ExecutionResult result = new HmacCreatorCallout(m).execute(msgCtxt, exeCtxt);

        // retrieve output
        String error = msgCtxt.getVariable("hmac.error");
        String hex = msgCtxt.getVariable("hmac.signature.hex");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(error, null);
        Assert.assertEquals(hex, "2987cef6200935ca2d7c4a70e690924438aa911e5ff589e7bcc15db55233aaa5");
    }

    @Test()
    public void messageTemplate() {
        msgCtxt.setVariable("var1", "a");
        msgCtxt.setVariable("var2", "b");
        msgCtxt.setVariable("var3", "c");

        Map m = new HashMap();
        m.put("string-to-sign", "{var1}{var2}{var3}");
        m.put("algorithm", "SHA-256");
        m.put("secret-key", "Secret123");

        ExecutionResult result = new HmacCreatorCallout(m).execute(msgCtxt, exeCtxt);

        // retrieve output
        String error = msgCtxt.getVariable("hmac.error");
        String hex = msgCtxt.getVariable("hmac.signature.hex");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(error, null);
        Assert.assertEquals(hex, "a7938720fe5749d31076e6961360364c0cd271443f1b580779932c244293bc94");
    }

    @Test()
    public void sha1_Probably_No_One_Should_Use_This() {
        Map m = new HashMap();
        m.put("string-to-sign", "testing123");
        m.put("key", "hello");
        m.put("algorithm", "SHA-1");
        m.put("debug", "true");

        ExecutionResult result = new HmacCreatorCallout(m).execute(msgCtxt, exeCtxt);

        // retrieve output
        String alg = msgCtxt.getVariable("hmac.alg");
        String error = msgCtxt.getVariable("hmac.error");
        String hex = msgCtxt.getVariable("hmac.signature.hex");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(alg, "SHA-1");
        Assert.assertEquals(error, null);
        Assert.assertEquals(hex.toLowerCase(), "ac2c2e614882ce7158f69b7e3b12114465945d01");
    }

    @Test()
    public void md5_Probably_No_One_Should_Use_This() {
        // set up
        Map m = new HashMap();
        m.put("string-to-sign", "testing123");
        m.put("key", "hello");
        m.put("algorithm", "MD-5");
        m.put("debug", "true");

        // run it
        ExecutionResult result = new HmacCreatorCallout(m).execute(msgCtxt, exeCtxt);

        // retrieve output
        String alg = msgCtxt.getVariable("hmac.javaizedAlg");
        //System.out.println("algorithm: " + alg);
        String error = msgCtxt.getVariable("hmac.error");
        //System.out.println("error: " + error);
        String hex = msgCtxt.getVariable("hmac.signature.hex");
        //System.out.println("hex: " + hex);

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(error, null);
        Assert.assertEquals(alg, "HmacMD5");
        Assert.assertEquals(hex.toLowerCase(), "1fcd2cdb3005f4d9baef9f3957cd2d1f");
    }

    @Test()
    public void knownOutcome_MD5_lowercase_nodash() {
        // set up
        Map m = new HashMap();
        m.put("string-to-sign", "testing123");
        m.put("key", "hello");
        m.put("algorithm", "md5");
        m.put("debug", "true");

        // run it
        ExecutionResult result = new HmacCreatorCallout(m).execute(msgCtxt, exeCtxt);

        // retrieve output
        String alg = msgCtxt.getVariable("hmac.javaizedAlg");
        //System.out.println("algorithm: " + alg);
        String error = msgCtxt.getVariable("hmac.error");
        //System.out.println("error: " + error);
        String hex = msgCtxt.getVariable("hmac.signature.hex");
        //System.out.println("hex: " + hex);

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(error, null);
        Assert.assertEquals(alg, "HmacMD5");
        Assert.assertEquals(hex.toLowerCase(), "1fcd2cdb3005f4d9baef9f3957cd2d1f");
    }

    @Test()
    public void verifyHmac1() {
        Map m = new HashMap();
        m.put("string-to-sign", "The quick brown fox...");
        m.put("key", "secret123");
        m.put("algorithm", "SHA-256");
        m.put("hmac-base64", "5tC369Qn1HqQ0IbiCpU6DOwHPDTMdFI/SuIAXrIdjj0=");
        m.put("debug", "true");

        ExecutionResult result = new HmacCreatorCallout(m).execute(msgCtxt, exeCtxt);

        // retrieve output
        String error = msgCtxt.getVariable("hmac.error");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(error, null);
    }

    @Test()
    public void verifyHmacFailure1() {
        Map m = new HashMap();
        m.put("string-to-sign", "The quick brown fox..!");
        m.put("key", "secret123");
        m.put("algorithm", "SHA-256");
        m.put("hmac-base64", "5tC369Qn1HqQ0IbiCpU6DOwHPDTMdFI/SuIAXrIdjj0=");
        m.put("debug", "true");

        ExecutionResult result = new HmacCreatorCallout(m).execute(msgCtxt, exeCtxt);

        // retrieve output
        String error = msgCtxt.getVariable("hmac.error");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.ABORT);
        Assert.assertEquals(error, "HMAC does not verify");
    }


}
