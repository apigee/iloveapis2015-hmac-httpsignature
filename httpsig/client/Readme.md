# HTTP Signature Client

This is a test client for the Http Signature API Proxy for Apigee Edge. 

It is a command-line application that uses nodejs . 
Tested and works on MacOS. 
Should also work on Windows clients, or Linux machines. 

## Pre-requisites: 

- node, v0.10 or later
- the HttpSignatureVerifier API proxy, imported and deployed to Apigee Edge


## To use: 

0. verify prerequisites

1. unpack the zip archive

2. open a terminal window or command prompt, to where you have unpacked and install the dependencies for the nodejs client app.  To do so, run this command: 

    ```npm install```

3. in the same terminal window, invoke the client app:
    ```node ./httpSigClient.js```

   This will display help.


## Example invocations

### Example 1: create an HMAC signature, and run hmac test 1: 

    node ./httpSigClient.js \
     -a hmac-sha256 \
     -k qFodTGAsLjC5sz0gKCjYEnCdQwVytVRm \
     -s ndEBookG4W2xAa8M  \
     -o sbuxeval1  -t hmac-t1 

(That command should run all on one line)

The -a option tells the client which algorithm to use. 
The -k option specifies the keyId to use in the signature. 
the -s option specifies the shared secret key to use for encryption. 

The -o option specifies the Apigee Edge organization. 

Finally, the -t option tells the client which path to use, in the API proxy. The client will emit some diagnostic messages, send out the request, and display the response. 

This command should succeed. You should see something like this as a response: 

    {
      "app.name" : "HttpSigApp",
      "apiproduct.name" : "HttpSigProduct",
      "signature" : {
        "keyId" : "qFodTGAsLjC5sz0gKCjYEnCdQwVytVRm",
        "algorithm" : "hmac-sha256",
        "headers" : "(request-target) date user-agent"
      },
      "verification": {
        "isValid" : "true",
        "requiredAlgorithm" : "hmac-sha256",
        "requiredHeaders" : "date (request-target)",
        "timeskew" : "0",
        "signingBase" : "(request-target): get /httpsig-java/hmac-t1?how=areyou|date: Thu, 20 Aug 2015 17:38:20 GMT|user-agent: nodejs httpSigClient.js",
        "computedSignature" : "9ABYB/HKXI/Ohzsxrem86dh4GNnp5VpXlEv7nozKE2I=",
        "error" : ""
      }
    }

Note the isValid indicates "true". 

Note: the -k and -s here are consumer ID and consumer secret, respectively.  The example API proxy provided with this client retrieves the secret key (consumer secret) based on the keyId. 

There are these paths available in the Apigee Edge example proxy provided with this client: 
  rsa-t1
  rsa-t2
  rsa-t3
  rsa-t4
  rsa-t5
  rsa-t6
  hmac-t1
  hmac-t2
  hmac-t3
  hmac-t4

### Example 2: create an HMAC signature, and use "the wrong" algorithm

    node ./httpSigClient.js \
     -a hmac-sha1 \
     -k qFodTGAsLjC5sz0gKCjYEnCdQwVytVRm \
     -s ndEBookG4W2xAa8M  \
     -o sbuxeval1  -t hmac-t1 

Same as above, but the client uses hmac-sha1.  The hmac-t1 path on the example API proxy REQUIRES hmac-sha256, therefore, the request is successfully sent by the client, but the proxy rejects the signature as it does not use the required algorithm .

    {
      "app.name" : "HttpSigApp",
      "apiproduct.name" : "HttpSigProduct",
      "signature" : {
        "keyId" : "qFodTGAsLjC5sz0gKCjYEnCdQwVytVRm",
        "algorithm" : "hmac-sha1",
        "headers" : "(request-target) date user-agent"
      },
      "verification": {
        "isValid" : "false",
        "requiredAlgorithm" : "hmac-sha256",
        "requiredHeaders" : "",
        "timeskew" : "",
        "signingBase" : "",
        "computedSignature" : "",
        "error" : "algorithm used in signature (hmac-sha1) is not as required (hmac-sha256)"
      }
    }

Note: isValid is false.

### Example 3: create an HMAC signature, but trigger proxy-side config error

    node ./httpSigClient.js \
     -a hmac-sha256 \
     -k qFodTGAsLjC5sz0gKCjYEnCdQwVytVRm \
     -s ndEBookG4W2xAa8M  \
     -o sbuxeval1  -t hmac-t2


The client sends the request to path /hmac-t2.  For this path, the HttpSignatureVerifier callout in the Apigee Edge proxy is purposefully configured incorrectly.  This demonstrates the behavior when incorrect configuration is used in the proxy.  

You should see a response like this: 

    {
      "app.name" : "HttpSigApp",
      "apiproduct.name" : "HttpSigProduct",
      "signature" : {
        "keyId" : "qFodTGAsLjC5sz0gKCjYEnCdQwVytVRm",
        "algorithm" : "hmac-sha256",
        "headers" : "(request-target) date user-agent"
      },
      "verification": {
        "isValid" : "false",
        "requiredAlgorithm" : "hmac-sha256",
        "requiredHeaders" : "date (request-target)",
        "timeskew" : "1",
        "signingBase" : "(request-target): get /httpsig-java/hmac-t2?how=areyou|date: Thu, 20 Aug 2015 17:31:58 GMT|user-agent: nodejs httpSigClient.js",
        "computedSignature" : "",
        "error" : "configuration error: secret-key is not specified or is empty."
      }
    }



### Example 4: demonstrate Apigee requiring signature on an additional header, success case

    node ./httpSigClient.js \
     -a hmac-sha256 \
     -k qFodTGAsLjC5sz0gKCjYEnCdQwVytVRm \
     -s ndEBookG4W2xAa8M  \
     -H app-specific-header:anything \
     -o sbuxeval1  -t hmac-t4


The flow at /hmac-t4 in the Edge proxy invokes a policy that requires that the HTTP Signature be computed on 3 headers: date (request-target) and app-specific-header. The client sets and signs the header named app-specific-header, and transmits that signature. Apigee Edge verifies this, and this request will succeed (return isValid = true).  Note: the signature verifier does not verify a "valid" value for app-specific-header. It only verifies that the signature is valid for a set of headers including app-sepcific-header. It's up to the app logic to determine whether the value of the signed header is valid. 



### Example 5: demonstrate Apigee Edge requiring signature on an additional header, failure case 

    node ./httpSigClient.js \
     -a hmac-sha256 \
     -k qFodTGAsLjC5sz0gKCjYEnCdQwVytVRm \
     -s ndEBookG4W2xAa8M  \
     -H other-header:anything \
     -o sbuxeval1  -t hmac-t4


The flow at /hmac-t4 in the Edge proxy invokes a policy that requires that the HTTP Signature be computed on 3 headers: date (request-target) and app-specific-header. This client does not set and sign 'app-specific-header', but rather, sets and signs 'other-header'. The resulting signature will not be accepted by the policy at Apigee Edge. 



### Example 6: create and send an RSA signature

    node ./httpSigClient.js \
     -a rsa-sha256 \
     -k qFodTGAsLjC5sz0gKCjYEnCdQwVytVRm \
     -p keys/key2-private.pem  \
     -o sbuxeval1  -t rsa-t4 

This one tells the lient to use RSA-sha256, with the private key as specified with the -p option. It sends the request to the /rsa-t4 path on the example API Proxy. The Verifier policy in Apigee Edge looks for an RSA signature with SHA of any key strength. This will succeed with a message like so: 

    {
      "app.name" : "HttpSigApp",
      "apiproduct.name" : "HttpSigProduct",
      "signature" : {
        "keyId" : "qFodTGAsLjC5sz0gKCjYEnCdQwVytVRm",
        "algorithm" : "rsa-sha256",
        "headers" : "(request-target) date user-agent"
      },
      "verification": {
        "isValid" : "true",
        "requiredAlgorithm" : "rsa-sha256",
        "requiredHeaders" : "date (request-target)",
        "timeskew" : "0",
        "signingBase" : "(request-target): get /httpsig-java/rsa-t4?how=areyou|date: Thu, 20 Aug 2015 17:40:11 GMT|user-agent: nodejs httpSigClient.js",
        "computedSignature" : "",
        "error" : ""
      }
    }


### Example 7: create and send an RSA signature and trigger a verification error

    node ./httpSigClient.js \
     -a rsa-sha256 \
     -k qFodTGAsLjC5sz0gKCjYEnCdQwVytVRm \
     -p keys/key2-private.pem  \
     -o sbuxeval1  -t rsa-t5

This one tells the client to use RSA-sha256, with the private key as specified with the -p option. It sends the request to the /rsa-t5 path on the example API Proxy.  

The Verification policy attached to the rsa-t5 path checks for RSA-sha1.  The verification will then fail, with a message like so: 

    {
      "app.name" : "HttpSigApp",
      "apiproduct.name" : "HttpSigProduct",
      "signature" : {
        "keyId" : "qFodTGAsLjC5sz0gKCjYEnCdQwVytVRm",
        "algorithm" : "rsa-sha256",
        "headers" : "(request-target) date user-agent"
      },
      "verification": {
        "isValid" : "false",
        "requiredAlgorithm" : "rsa-sha1",
        "requiredHeaders" : "",
        "timeskew" : "",
        "signingBase" : "",
        "computedSignature" : "",
        "error" : "algorithm used in signature (rsa-sha256) is not as required (rsa-sha1)"
      }
    }




### Example 8: create and send an RSA signature using rsa-sha1

    node ./httpSigClient.js \
     -a rsa-sha1 \
     -k qFodTGAsLjC5sz0gKCjYEnCdQwVytVRm \
     -p keys/key2-private.pem  \
     -o sbuxeval1  -t rsa-t5

This is like Example 5, but the client uses rsa-sha1. 

The Verification policy attached to the rsa-t5 path checks for RSA-sha1.  The verification will then succeed, with a message like so: 

    {
      "app.name" : "HttpSigApp",
      "apiproduct.name" : "HttpSigProduct",
      "signature" : {
        "keyId" : "qFodTGAsLjC5sz0gKCjYEnCdQwVytVRm",
        "algorithm" : "rsa-sha1",
        "headers" : "(request-target) date user-agent"
      },
      "verification": {
        "isValid" : "true",
        "requiredAlgorithm" : "rsa-sha1",
        "requiredHeaders" : "date (request-target)",
        "timeskew" : "1",
        "signingBase" : "(request-target): get /httpsig-java/rsa-t5?how=areyou|date: Thu, 20 Aug 2015 17:43:20 GMT|user-agent: nodejs httpSigClient.js",
        "computedSignature" : "",
        "error" : ""
      }
    }


### Example 9: RSA, test missing header

    node ./httpSigClient.js \
     -a rsa-sha256 \
     -k qFodTGAsLjC5sz0gKCjYEnCdQwVytVRm \
     -p keys/key2-private.pem  \
     -o sbuxeval1  -t rsa-t3

This one tells the lient to use RSA-sha256, with the private key as specified with the -p option. It sends the request to the /rsa-t3 path on the example API Proxy.  

The Verify policy attached to the rsa-t3 flow checks for the presence of the nonce header in the signature. This client invocation does not send such a header, therefore the verification will fail. 

You will see a message like so: 

    {
      "app.name" : "HttpSigApp",
      "apiproduct.name" : "HttpSigProduct",
      "signature" : {
        "keyId" : "qFodTGAsLjC5sz0gKCjYEnCdQwVytVRm",
        "algorithm" : "rsa-sha256",
        "headers" : "(request-target) date user-agent"
      },
      "verification": {
        "isValid" : "false",
        "requiredAlgorithm" : "",
        "requiredHeaders" : "date (request-target) nonce",
        "timeskew" : "",
        "signingBase" : "",
        "computedSignature" : "",
        "error" : "signature is missing required header (nonce)."
      }
    }



### Example 10: send the nonce header

    node ./httpSigClient.js \
     -a rsa-sha256 \
     -n 12345 \
     -k qFodTGAsLjC5sz0gKCjYEnCdQwVytVRm \
     -p keys/key2-private.pem  \
     -o sbuxeval1  -t rsa-t3

This one is like Example 7,  but the client actually sends the required nonce header and includes that header in the signature. 

The Verify policy attached to the rsa-t3 flow checks for the presence of the nonce header in the signature. The verification will succeed. 

You will see a message like so: 

    {
      "app.name" : "HttpSigApp",
      "apiproduct.name" : "HttpSigProduct",
      "signature" : {
        "keyId" : "qFodTGAsLjC5sz0gKCjYEnCdQwVytVRm",
        "algorithm" : "rsa-sha256",
        "headers" : "(request-target) date user-agent nonce"
      },
      "verification": {
        "isValid" : "true",
        "requiredAlgorithm" : "",
        "requiredHeaders" : "date (request-target) nonce",
        "timeskew" : "0",
        "signingBase" : "(request-target): get /httpsig-java/rsa-t3?how=areyou|date: Thu, 20 Aug 2015 17:47:57 GMT|user-agent: nodejs httpSigClient.js|nonce: 12345",
        "computedSignature" : "",
        "error" : ""
      }
    }
