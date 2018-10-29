// NotImplementedException.java
// ------------------------------------------------------------------
package com.google.apigee.testng.support;

public class NotImplementedException extends RuntimeException {
    String msg;
    private static final long serialVersionUID = 1L;

    public NotImplementedException(){
        msg = "Not implemented";
    }

    public NotImplementedException(String message){
        msg = message;
    }

    @Override
    public String getMessage() {
        return msg;
    }
}
