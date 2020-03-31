package com.google.apigee.callout.httpsignature;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface KeyProvider {
    public byte[] getSecretKey() throws IllegalStateException;
    public PublicKey getPublicKey() throws Exception;
    public PrivateKey getPrivateKey() throws Exception;
}
