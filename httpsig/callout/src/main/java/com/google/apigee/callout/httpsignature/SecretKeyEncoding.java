package com.google.apigee.callout.httpsignature;

import java.util.Optional;

public enum SecretKeyEncoding {
  HEX, BASE16, BASE64, BASE64URL, UTF8;

  public static Optional<SecretKeyEncoding> getValueOf(String name) {
    try {
        return Optional.of(Enum.valueOf(SecretKeyEncoding.class, name));
    } catch(IllegalArgumentException ex) {
        return Optional.empty();
    }
  }

}
