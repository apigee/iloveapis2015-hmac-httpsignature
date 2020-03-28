package com.google.apigee.callout.httpsignature;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SignatureParser {

  enum ParseState  {
    BEGIN,
    NAME,
    VALUE,
    COMMA,
    QUOTE,
    INTEGER
  }

  private static final List<String> requiredHdrParams = Arrays.asList(new String[] {
   "algorithm", "keyId", "signature"
    });

  private static final List<String> validHdrParams = Arrays.asList(new String[] {
    "algorithm", "keyId", "signature", "headers", "created", "expires"
    });

  private static final List<String> validAlgorithms = Arrays.asList(new String[] {
    "rsa-sha256", "hmac-sha256", "hs2019"
    });

  private static void checkNameChar(char code) {
    if ((code >= 0x41 && code <= 0x5a) || // A-Z
        (code >= 0x61 && code <= 0x7a)) { // a-z
    }
    else if (code == 0x20) {
      throw new IllegalStateException("invalid whitespace before parameter name");
    }
    else {
      throw new IllegalStateException("invalid parameter name");
    }
  }

  private static void checkIntegerChar(char code) {
    if (code < 0x30 || code >0x39) { // 0-9
      throw new IllegalStateException("invalid integer value");
    }
  }

  public static Map<String,Object> parse(String str) {
    if (str == null || str.equals("")) {
      throw new IllegalStateException("missing value for Signature.");
    }
    str = str.trim();

    // In some drafts of the specification, there is a keyword "Signature"
    // prefix. I think at least drafts 3 and 4 omit that.  Try to observe
    // Postel's law here.
    //
    if (str.toLowerCase().startsWith("signature ")) {
      str = str.substring(10, str.length());
    }

    ParseState state = ParseState.NAME;
    String name = "";
    String value = "";
    Map<String, Object> parsed = new HashMap<String,Object>();
    int i = 0;
    do {
      char c = str.charAt(i);

      switch (state) {

        case NAME:
          if (c == '=') {
            if (parsed.containsKey(name))
              throw new IllegalStateException("duplicate auth-param at position " + i);

            state = (name.equals("created") || name.equals("expires")) ? ParseState.INTEGER : ParseState.QUOTE;
          }
          else if (c == ' ') {
            /* skip OWS between auth-params */
            if (name != "")
              throw new IllegalStateException("whitespace in name at position " + i);
          }
          else {
            checkNameChar(c);
            name += c;
          }
          break;

        case INTEGER:
          if (c == ',') {
            // this must be a seconds-since-epoch  eg, 1402170695
            if (value.length() != 10)
              throw new IllegalStateException("bad value (" + value + " at posn " + i);

            state = ParseState.NAME;
            parsed.put(name,value);
            name = "";
            value = "";
          }
          else {
            checkIntegerChar(c);
            value += c;
          }
          break;

        case QUOTE:
          if (c == '"') {
            value = "";
            state = ParseState.VALUE;
          } else {
            throw new IllegalStateException("expecting quote at position " + i);
          }
          break;

        case VALUE:
          if (name.length() == 0)
            throw new IllegalStateException("bad param name at posn " + i);
          if (c == '"') {
            parsed.put(name,value);
            state = ParseState.COMMA;
          } else {
            value += c;
          }
          break;

        case COMMA:
          if (c == ',') {
            name = "";
            value = "";
            state = ParseState.NAME;
          } else {
            throw new IllegalStateException("bad param format");
          }
          break;

        default:
          throw new IllegalStateException("Invalid format at posn " + i);
      }

      i++;
    } while (i < str.length());


    requiredHdrParams
    .forEach( key -> {
        if (!parsed.containsKey(key))
            throw new IllegalStateException("missing parameter: " + key);
      });

    parsed.keySet()
    .stream()
    .forEach(key -> {
        if (validHdrParams.indexOf(key) < 0)
          throw new IllegalStateException("unsupported header parameter: " + key);
        if (parsed.get(key).equals(""))
          throw new IllegalStateException("empty header parameter: " + key);
      });

    if (validAlgorithms.indexOf(parsed.get("algorithm")) < 0) {
      throw new IllegalStateException("unsupported algorithm: " + parsed.get("algorithm"));
    }

    if (parsed.containsKey("headers")) {
      // convert to a list
      List<String> list = Arrays.asList(((String)parsed.get("headers")).split("\\s+"));
      parsed.put("headers", list);

      // Verify that if the times are asserted, they are present,
      // and that the alg is hs2019
      Arrays.asList(new String[] { "created", "expires"})
        .forEach( s -> {
            if (list.indexOf(s)>=0) {
              if (!parsed.containsKey(s))
                throw new IllegalStateException("missing parameter: " + s);
              if (!parsed.get("algorithm").equals("hs2019"))
                throw new IllegalStateException("unacceptable parameter: " + s);
              parsed.put(s, Integer.valueOf((String)(parsed.get(s))));
            }
          });
    }

    return parsed;
  }
}
