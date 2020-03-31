package com.google.apigee.callout;

import com.apigee.flow.execution.ExecutionResult;
import com.google.apigee.callout.httpsignature.SignatureGeneratorCallout;
import java.util.HashMap;
import java.util.Map;
import org.testng.Assert;
import org.testng.annotations.Test;

public class TestHttpSigGeneratorCallout extends CalloutTestBase {

    //private static final String[] encodedKeys = new String[] {};
  private static final String privateRsaKey1 = ""
+ "-----BEGIN PRIVATE KEY-----\n"
+ "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCpepGhIKzEvlWZ\n"
+ "VKkgOC0MB59SVLsb2sQ21rxKdb9wzX1p0FIUgWHmVPwsJyrtrDY2jLF2j9NyEW5t\n"
+ "sY18/6cURU341T6egIMdTKXkVAEcVEiFZuTh63Inj12ovzPTWTQU+N5KI01LFFXO\n"
+ "laAvbbUz/LQibu/wO4pPz2/XrUNwR2NsnnSOMzcj+RYElrAOVwPrbI0yiDH1x0dd\n"
+ "TCBGb9XZd9ip0BHEsqjfzg41PxmlTDygXzdLy2aEJdw4h2Zj4BDGlhCgf+sAB017\n"
+ "vshRdGlao9Rm+DO3261muE/tqBoAp+D5lzQ9InPix/Dd7abBV95b9sm+B5P7uM6f\n"
+ "01qEhzATAgMBAAECggEAOidswTVNE1WcWbjLL9sW2gHjkYSxj6VJnuegRIyS3Eom\n"
+ "tqBdCdw7k6WlwiDOgi+NirpMSrqfe4yvr8Q1IKc41aPSVYgWrJy8YNlkMy0AFJB3\n"
+ "Mg9UipEX4qs3ICg7yFHbpTagUCA87X5U00ZUaPHkM6qKxSX7/xrvIuOzJPa3JVdK\n"
+ "RKZfp/fA2Abrwi55aqgduT9Izkw2PTI9nOzCRS0rQXjNhCywiZc+8BusLwKwsZkv\n"
+ "UkkqK3BQysX1lvKCDWmAsibLyTcD9dW2cP3OjKjLeA8BBLy9Wbc0O7K6qo/dKIg4\n"
+ "szSPV1N1/AFCeZtG1QjdnS9Iw5xE3vo/U6lI7RKhAQKBgQDhyzInoPDjEDVm6+Yz\n"
+ "d0woqJ1fDaVQRG17ipUPIzHCVBDbsGXQBQeP+kwnp4pW6bfRi/NMY4rLpgUsF22o\n"
+ "TSy42K3X1u4jk6x8060RWg9DhyHrfl9W3AnPeXoZ2ZXeh+9KltSiKMwErZhT2My1\n"
+ "uAegz4ob041MM395SNwvtcOFMQKBgQDAJr5OZx5YohxYBSzB4ctI5QpaV0hIZ5P1\n"
+ "XGMb3KtD5SmeNDjAcp/7CFuaHVZqKcEIUcw4Q9deuc392Q/8kGv3K6itij5Mmsgk\n"
+ "dNbMERWkOQXzP4ERydO2L9Pb8vvVAy2wwd6AGCF2Oe4mmGpuQVNOgoh6s4EyQKEs\n"
+ "YbRzgDiIgwKBgQChXCgsn9xmOKghNEZf00qO5+kHC+ZvFWe0WRYrKjieKpudlFM+\n"
+ "NMnxv6r6z8WSVRYzXzNxDNYcsTmTB+8qznQ+aULbM9Mdg6RJ1LAi7VxpIsI/3CDg\n"
+ "HwG3zpVOsetji3ubr2ynskYStchda1roJmr1JjwJpMaehVL85u/L/LaMkQKBgAa5\n"
+ "FE1/9CLbwSwfOjqqYMdzJBKXHTNTVGzwR5Nw/BkLCpK7dwTcvdY1q6bPwfdC8LsO\n"
+ "yZtqXD23OIraLmIC15Q1VdiEjrt1au1DnURUkLJHQHsLTMPHkP293KbEcKU6UD3v\n"
+ "+o32yiztx/RXvtmOtZB4prfMUgflFP6NiJfF87RrAoGBALx+Umcf2mQod/7Oj2hL\n"
+ "f0916ng35qByFVo6xSuT3+FAGUYAzmmZ4H/LnMs4N9H96XI5+CPJJNqBPviOhtoR\n"
+ "7Ilqe+NNDb4zJX5xNFv6Bp1A4h4P33jpCBvbjVh6j5AVk7vDSdWdITKaTDx5z3zC\n"
+ "xbiTIJLDzgKP5rTUxxzzVzUK\n"
      + "-----END PRIVATE KEY-----\n";


  private void checkSignatureComponents(String output, String... requisites) {
    for (String item : requisites) {
      Assert.assertTrue(output.indexOf(item)>=0, item);
    }
  }

  @Test()
  public void hmac_Generate1(){
    Map properties = new HashMap();
    properties.put("keyId", "hmac_Generate1");
    properties.put("secret-key", "Secret1234567890ABCDEFGHIJKLMNOP");
    properties.put("algorithm", "hmac-sha256");
    properties.put("headers", "x-request-id");
    properties.put("debug", "true");

    msgCtxt.setVariable("request.header.x-request-id", "00000000-0000-0000-0000-000000000004");

    SignatureGeneratorCallout callout = new SignatureGeneratorCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    String error = msgCtxt.getVariable("httpsig_error");
    Assert.assertNull(error);

    String signature = msgCtxt.getVariable("httpsig_signature");
    Assert.assertEquals(signature, "zLLFGuErvRxpMEOPv3WwPoktkUeHL8Apltb2f1WrrBs=");

    String output = msgCtxt.getVariable("httpsig_output");
    Assert.assertNotNull(output);
    checkSignatureComponents(output,
                   "keyId=\"hmac_Generate1\"",
                   "algorithm=\"hmac-sha256\"",
                   "headers=\"x-request-id\"",
                   "signature=\"zLLFGuErvRxpMEOPv3WwPoktkUeHL8Apltb2f1WrrBs=\"");
  }

  @Test()
  public void hmac_Generate2() {
    Map properties = new HashMap();
    properties.put("keyId", "hmac_Generate2");
    properties.put("secret-key", "Secret1234567890ABCDEFGHIJKLMNOP");
    properties.put("algorithm", "hmac-sha256");
    //properties.put("headers", "request.header.x-request-id");
    properties.put("debug", "true");

    msgCtxt.setVariable("proxy.url", "/foobar/baz");
    msgCtxt.setVariable("request.verb", "GET");

    SignatureGeneratorCallout callout = new SignatureGeneratorCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    String error = msgCtxt.getVariable("httpsig_error");
    Assert.assertNull(error);

    String signature = msgCtxt.getVariable("httpsig_signature");
    Assert.assertNotNull(signature);

    String output = msgCtxt.getVariable("httpsig_output");
    Assert.assertNotNull(output);
    checkSignatureComponents(output,
                             "keyId=\"hmac_Generate2\"",
                             "algorithm=\"hmac-sha256\"",
                             "headers=\"(request-target)\"");
  }

  @Test()
  public void hmac_Generate_Created1(){
    Map properties = new HashMap();
    properties.put("keyId", "hmac_Generate_Created1");
    properties.put("secret-key", "Secret1234567890ABCDEFGHIJKLMNOP");
    properties.put("algorithm", "hmac-sha256");
    properties.put("include-created", "true");
    properties.put("expires-in", "10m");
    properties.put("headers", "x-request-id created");
    properties.put("debug", "true");

    msgCtxt.setVariable("request.header.x-request-id", "00000000-0000-0000-0000-000000000004");

    SignatureGeneratorCallout callout = new SignatureGeneratorCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // should fail because created is not supported with hmac-sha256
    Assert.assertEquals(result, ExecutionResult.ABORT);

    String error = msgCtxt.getVariable("httpsig_error");
    Assert.assertNotNull(error);
    Assert.assertEquals(error,"invalid parameter: created");
  }

  @Test()
  public void hs2019_hmac_Generate_Created(){
    Map properties = new HashMap();
    properties.put("keyId", "hs2019_hmac_Generate_Created");
    properties.put("secret-key", "Secret1234567890ABCDEFGHIJKLMNOP");
    properties.put("algorithm", "hs2019");
    properties.put("hs2019-algorithm", "hmac");
    properties.put("include-created", "true");
    properties.put("expires-in", "10m");
    properties.put("headers", "x-request-id");
    properties.put("debug", "true");

    msgCtxt.setVariable("request.header.x-request-id", "00000000-0000-0000-0000-000000000004");

    SignatureGeneratorCallout callout = new SignatureGeneratorCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    String error = msgCtxt.getVariable("httpsig_error");
    Assert.assertNull(error);
    String headers = msgCtxt.getVariable("httpsig_headers");
    Assert.assertEquals(headers, "x-request-id created expires");

    String output = msgCtxt.getVariable("httpsig_output");
    Assert.assertNotNull(output);
    checkSignatureComponents(output,
                             "created=",
                             "expires=",
                             "keyId=\"hs2019_hmac_Generate_Created\"",
                             "headers=",
                             "signature=");
  }

  @Test()
  public void rsa_Generate1() {
    Map properties = new HashMap();
    properties.put("keyId", "rsa_Generate1");
    properties.put("private-key", privateRsaKey1);
    properties.put("algorithm", "rsa-sha256");
    //properties.put("headers", "request.header.x-request-id");
    properties.put("debug", "true");

    msgCtxt.setVariable("proxy.url", "/foobar/baz");
    msgCtxt.setVariable("request.verb", "GET");

    SignatureGeneratorCallout callout = new SignatureGeneratorCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    String error = msgCtxt.getVariable("httpsig_error");
    Assert.assertNull(error);

    String signature = msgCtxt.getVariable("httpsig_signature");
    Assert.assertNotNull(signature);

    String output = msgCtxt.getVariable("httpsig_output");
    Assert.assertNotNull(output);
    checkSignatureComponents(output,
                             "keyId=\"rsa_Generate1\"",
                             "algorithm=\"rsa-sha256\"",
                             "headers=\"(request-target)\"");
  }

  @Test()
  public void rsa_Generate_BadKey() {
    Map properties = new HashMap();
    properties.put("keyId", "rsa_Generate1");
    properties.put("private-key", "When you realize nothing is lacking, the whole world belongs to you.");
    properties.put("algorithm", "rsa-sha256");
    properties.put("headers", "request.header.x-request-id");
    properties.put("debug", "true");

    msgCtxt.setVariable("request.header.x-request-id", "00000000-0000-0000-0000-000000000004");

    SignatureGeneratorCallout callout = new SignatureGeneratorCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(result, ExecutionResult.ABORT); // bad private key

    String error = msgCtxt.getVariable("httpsig_error");
    Assert.assertNotNull(error);
    Assert.assertEquals(error, "cannot read private key");

    String signature = msgCtxt.getVariable("httpsig_signature");
    Assert.assertNull(signature);
  }

  @Test()
  public void hs2019_rsa_Generate_Created(){
    Map properties = new HashMap();
    properties.put("keyId", "hs2019_rsa_Generate_Created");
    properties.put("private-key", privateRsaKey1);
    properties.put("algorithm", "hs2019");
    properties.put("hs2019-algorithm", "rsa");
    properties.put("include-created", "true");
    properties.put("expires-in", "10m");
    properties.put("headers", "x-request-id");
    properties.put("debug", "true");

    msgCtxt.setVariable("request.header.x-request-id", "00000000-0000-0000-0000-000000000004");

    SignatureGeneratorCallout callout = new SignatureGeneratorCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    String error = msgCtxt.getVariable("httpsig_error");
    Assert.assertNull(error);
    String headers = msgCtxt.getVariable("httpsig_headers");
    Assert.assertEquals(headers, "x-request-id created expires");

    String output = msgCtxt.getVariable("httpsig_output");
    Assert.assertNotNull(output);
    checkSignatureComponents(output,
                             "created=",
                             "expires=",
                             "keyId=\"hs2019_rsa_Generate_Created\"",
                             "headers=\"x-request-id created expires\"",
                             "signature=");
  }

}
