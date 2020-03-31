package com.google.apigee.callout;

import com.google.apigee.callout.httpsignature.SignatureParser;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.IntStream;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.testng.Assert;

public class TestSignatureParser {

  // @DataProvider requires the output to be a Object[][]. The inner
  // Object[] is the set of params that get passed to the test method.
  // So, if you want to pass just one param to the constructor, then
  // each inner Object[] must have length 1.

  protected Object[][] toDataProvider(String[] a) {
    ArrayList<Object[]> list = new ArrayList<Object[]>();

    IntStream.range(0, a.length)
      .forEach( i -> list.add(new Object[] { i, a[i] }));
    return list.toArray(new Object[list.size()][]);
  }

  @DataProvider(name = "invalid")
  protected Object[][] getInvalidSignatures() {
    String[] testcases = new String[] {
      // not even close
      "The quick brown fox...",

      // missing required params
      "Signature algorithm=\"hmac-sha256\"",

      // missing required params
      "Signature algorithm=\"hmac-sha256\", headers=\"date\"",

      // missing required params
      "Signature algorithm=\"hmac-sha256\", headers=\"date\", keyId=\"abc\"",

      // unknown is not a known param name
      "Signature algorithm=\"hmac-sha256\", headers=\"date\", keyId=\"abc\", unknown=\"abc==\"",

      // headers must get a quoted string
      "Signature algorithm=\"hmac-sha256\", headers=date, keyId=\"abc\", signature=\"abc==\"",

      // missing comma
      "Signature algorithm=\"hmac-sha256\", headers=\"date\" keyId=\"abc\", signature=\"abc==\"",

      // hmac not a valid alg
      "Signature algorithm=\"hmac\", headers=\"date\", keyId=\"abc\", signature=\"abc==\"",

      // created is not supported with hmac-sha256
      "Signature algorithm=\"hmac-sha256\", created=1585351097, headers=\"date created\", keyId=\"abc\", signature=\"abc==\"",

      // created is not supported with rsa-sha256
      "Signature algorithm=\"rsa-sha256\", created=1585351097, headers=\"date created\", keyId=\"abc\", signature=\"abc==\"",

      // expires is not supported with hmac-sha256
      "Signature algorithm=\"hmac-sha256\", expires=1585351097, headers=\"date expires\", keyId=\"abc\", signature=\"abc==\"",

      // expires is not supported with rsa-sha256
      "Signature algorithm=\"rsa-sha256\", expires=1585351097, headers=\"date expires\", keyId=\"abc\", signature=\"abc==\"",

      // expires must be an integer
      "Signature algorithm=\"hs2019\", expires=\"1585351097\", headers=\"date expires\", keyId=\"abc\", signature=\"abc==\"",

      // created must be an integer
      "Signature algorithm=\"hs2019\", created=\"1585351097\", headers=\"date created\", keyId=\"abc\", signature=\"abc==\"",

      // created asserted but not present
      "Signature algorithm=\"hs2019\", headers=\"date created\", keyId=\"abc\", signature=\"abc==\"",

      // duplicate param name
      "Signature keyId=\"abc\", keyId=\"abc\", algorithm=\"hs2019\", headers=\"date created\", signature=\"abc==\"",

      // empty signature value
      "Signature algorithm=\"hs2019\", headers=\"something\", keyId=\"abc\", signature=\"\"",

      // empty algorithm value
      "Signature algorithm=\"\", headers=\"something\", keyId=\"abc\", signature=\"abc==\"",

      // empty keyId value
      "Signature algorithm=\"hs2019\", headers=\"something\", keyId=\"\", signature=\"abc==\"",

      // empty headers value
      "Signature algorithm=\"hs2019\", headers=\"\", keyId=\"something\", signature=\"abc==\""
    };
    return toDataProvider(testcases);
  }

  @DataProvider(name = "good")
  protected Object[][] getGoodSignatures() {
    String[] testcases = new String[] {
      "Signature algorithm=\"hmac-sha256\", headers=\"date\", keyId=\"abc\", signature=\"abc==\"",
      "Signature algorithm=\"rsa-sha256\", headers=\"date\", keyId=\"abc\", signature=\"abc==\"",
      "Signature algorithm=\"hs2019\", created=1585351097, headers=\"date created\", keyId=\"abc\", signature=\"abc==\"",
      "Signature algorithm=\"hs2019\", created=1585351097, expires=1585351397, headers=\"date expires created\", keyId=\"abc\", signature=\"abc==\"",
      "Signature keyId=\"abc\", algorithm=\"hs2019\", created=1585351097, expires=1585351397, headers=\"date expires created\", signature=\"abc==\"",
      "Signature algorithm=\"hmac-sha256\", keyId=\"abc\", signature=\"abc==\""
    };
    return toDataProvider(testcases);
  }

  @Test(dataProvider = "invalid")
  public void invalidSignatures(int ix, String s) {
    try {
      Map<String,Object> result = SignatureParser.parse(s);
      Assert.fail("test "+ ix + " unexpected success");
    }
    catch (IllegalStateException ex1) {
    }
  }

  @Test(dataProvider = "good")
  public void goodSignatures(int ix, String s) {
    try {
      Map<String,Object> result = SignatureParser.parse(s);
    }
    catch (Exception ex1) {
      Assert.fail("test "+ ix + " failed: "+ ex1.getMessage());
    }
  }


}
