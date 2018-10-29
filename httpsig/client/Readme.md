# HTTP Signature Client

This is a test client for the Http Signature API Proxy for Apigee Edge.

It is a command-line application that uses nodejs .
Tested and works on MacOS.
Should also work on Windows clients, or Linux machines.

## Pre-requisites:

- node, v6.2 or later
- the HttpSignatureVerifier API proxy, imported and deployed to Apigee Edge


## To use:

1. verify prerequisites

2. unpack the zip archive

3. open a terminal window or command prompt, to where you have unpacked and install the dependencies for the nodejs client app.  To do so, run this command:

    ```npm install```

4. configure the required API Product and Developer, and Developer App within Apigee Edge.

5. in the same terminal window, invoke the client app:
    ```node ./httpSigClient.js```

   This will display help.


## Notes on configuring the API Product, etc

The client here relies on the consumer secret to be the shared secret for computing HMACs.  Therefore, in order
to get this all to work, you will need the API Proxy to be created. See the [apiproxy sibling directory](../apiproxy) for how to do that.  You also need an API Product, which must contain the API Proxy.  And you also need a Developer app, with a client_id and client_secret (aka consumer id and consumer secret).   And you need to create a cache, called cache1, in the environment to support the nonces.
If you wish to use RSA encryption, then you will need to separately generate an RSA keypair, and you will
need to set the PEM-encoded public key as a custom attribute, called public_key, on the developer app.


Creating the API Product and the Developer and the Developer App in Apigee Edge is typically a manual step.  Likewise setting a custom attribute on a developer app, and creating a cache. You can do all of this using the Publish section of the administrative UI.

However, this directory contains a provisioning script that can do it for you automatically.


```
./provisionApiProductAndApp.sh -u USERNAME:PASSWORD -o ORGNAME  -d
```

In the examples that follow, the consumer secret generated for the developer app will be used as the
shared secret for HMAC encryption. This is not required by the HMAC standard; in fact you can
use any shared secret key.  But it is probably a good practice
to use the consumer secret as the shared secret when computing or verifying HMACs in Edge.

The provisioning script mentioned above uses a pre-generated public/private key pair, and sets the public key as
the custom attribute. This means for RSA signatures, you will use the private key on the client to compute the signature  and the public key in the Edge API proxy, to validate the RSA signature.

The output of the above script will finish with something like this:

```
  consumer key: AGX1FHKYWtGlAlrSsZTZ2GaZUR85FzUV
  consumer secret: fVJKiTJ61FD3b3UE
```

You will need to use those as the values for the -k and the -s options, respectively, in the invocations that follow.
Every invocation uses the -k option; only those invocations that use HMAC will use the -s option.


## Example invocations

### Example 1: create an HMAC signature, and run hmac test 1:

    node ./httpSigClient.js \
     -a hmac-sha256 \
     -k CONSUMER_KEY_HERE \
     -s CONSUMER_SECRET_HERE  \
     -o ORG_NAME_HERE  -t hmac-t1

(That command should run all on one line)

You will need to specify your own settings for these items

* The -k option specifies the consumer key, aka keyId to use in the signature.
* the -s option specifies the shared consumer secret, aka secret key to use for encryption.
* The -o option specifies the Apigee Edge organization.

The -k and -s come from the developer app which you have registered in the Edge organization, possibly via the automated provisioning script. This app must have access to the httpsig API Proxy.

The -a option tells the client which algorithm to use. For this first invocation, you will use hmac-sha256.

Finally, the -t option tells the client which path to use, in the API proxy. The client will emit some diagnostic messages, send out the request, and display the response.

This command should succeed. You should see something like this as a response:

```json
{
  "app.name" : "HttpSigApp",
  "apiproduct.name" : "HttpSigProduct",
  "signature" : {
    "keyId" : "CONSUMER_KEY_HERE",
    "algorithm" : "hmac-sha256",
    "headers" : "(request-target) date user-agent"
  },
  "verification": {
    "isValid" : "true",
    "requiredAlgorithm" : "hmac-sha256",
    "requiredHeaders" : "date (request-target)",
    "timeskew" : "0",
    "signingBase" : "(request-target): get /httpsig/hmac-t1?how=areyou|date: Thu, 20 Aug 2015 17:38:20 GMT|user-agent: nodejs httpSigClient.js",
    "computedSignature" : "9ABYB/HKXI/Ohzsxrem86dh4GNnp5VpXlEv7nozKE2I=",
    "error" : ""
  }
}
```

Note the isValid property indicates "true".

Note: the -k and -s here are consumer key and consumer secret, respectively.  The example API proxy provided with this client retrieves the secret key (consumer secret) based on the passed-in consumer key (aka KeyId).

There are these paths available in the Apigee Edge example proxy provided with this client:

* rsa-t1
* rsa-t2
* rsa-t3
* rsa-t4
* rsa-t5
* rsa-t6
* hmac-t1
* hmac-t2
* hmac-t3
* hmac-t4


### Example 2: create an HMAC signature, and use "the wrong" algorithm

    node ./httpSigClient.js \
     -a hmac-sha1 \
     -k CONSUMER_KEY_HERE \
     -s CONSUMER_SECRET_HERE  \
     -o ORG_NAME_HERE  -t hmac-t1

Same as above, but the client uses hmac-sha1.  The hmac-t1 path on the example API proxy REQUIRES hmac-sha256, therefore, the request is successfully sent by the client, but the proxy rejects the signature as it does not use the required algorithm . The response:

```
{
  "error" : "algorithm used in signature (hmac-sha1) is not as required (hmac-sha256)"
}
```


### Example 3: create an HMAC signature, but trigger proxy-side config error

    node ./httpSigClient.js \
     -a hmac-sha256 \
     -k CONSUMER_KEY_HERE \
     -s CONSUMER_SECRET_HERE  \
     -o ORG_NAME_HERE  -t hmac-t2


The client sends the request to path /hmac-t2.  For this path, the HttpSignatureVerifier callout in the Apigee Edge proxy is purposefully configured incorrectly.  This demonstrates the behavior when incorrect configuration is used in the proxy.

You should see a response like this:
```
{
  "error" : "configuration error: secret-key is not specified or is empty."
}
```


The Java source code is currently configured to NOT return a fault in case of error.  This includes either errors in configuration, such as this case (the secret-key was not confgured), or errors in signature validation. Instead the Java callout sets context variables which your API Proxy flow must test in order to determine next steps.

It might be reasonable to want the Java callout to behave differently in the case of failure - for example to throw an exception, which would put the Apigee Edge flow processing into Fault state.  This means [the Fault Rules apply](http://apigee.com/docs/api-services/content/fault-handling).


### Example 4: demonstrate Apigee requiring signature on an additional header, success case

    node ./httpSigClient.js \
     -a hmac-sha256 \
     -k CONSUMER_KEY_HERE \
     -s CONSUMER_SECRET_HERE  \
     -H app-specific-header:anything \
     -o ORG_NAME_HERE  -t hmac-t4


The flow at /hmac-t4 in the Edge proxy invokes a policy that requires that the HTTP Signature be computed on 3 headers: date (request-target) and app-specific-header. The client sets and signs the header named app-specific-header, and transmits that signature. Apigee Edge verifies this, and this request will succeed (return isValid = true).  Note: the signature verifier does not verify a "valid" value for app-specific-header. It only verifies that the signature is valid for a set of headers including app-sepcific-header. It's up to the app logic to determine whether the value of the signed header is valid.



### Example 5: demonstrate Apigee Edge requiring signature on an additional header, failure case

    node ./httpSigClient.js \
     -a hmac-sha256 \
     -k CONSUMER_KEY_HERE \
     -s CONSUMER_SECRET_HERE  \
     -H other-header:anything \
     -o ORG_NAME_HERE  -t hmac-t4


The flow at /hmac-t4 in the Edge proxy invokes a policy that requires that the HTTP Signature be computed on 3 headers: date (request-target) and app-specific-header. This client does not set and sign 'app-specific-header', but rather, sets and signs 'other-header'. The resulting signature will not be accepted by the policy at Apigee Edge.

You will see a result like this:

```
==> 500
body:
{
  "error" : "signature is missing required header (app-specific-header)."
}
```


### Example 6: create and send an RSA signature

    node ./httpSigClient.js \
     -a rsa-sha256 \
     -k CONSUMER_KEY_HERE \
     -p keys/key2-private.pem  \
     -o ORG_NAME_HERE  -t rsa-t4

This one tells the lient to use RSA-sha256, with the private key as specified with the -p option. It sends the request to the /rsa-t4 path on the example API Proxy. The Verifier policy in Apigee Edge looks for an RSA signature with SHA of any key strength. This will succeed with a message like so:

    {
      "app.name" : "HttpSigApp",
      "apiproduct.name" : "HttpSigProduct",
      "signature" : {
        "keyId" : "CONSUMER_KEY_HERE",
        "algorithm" : "rsa-sha256",
        "headers" : "(request-target) date user-agent"
      },
      "verification": {
        "isValid" : "true",
        "requiredAlgorithm" : "rsa-sha256",
        "requiredHeaders" : "date (request-target)",
        "timeskew" : "0",
        "signingBase" : "(request-target): get /httpsig/rsa-t4?how=areyou|date: Thu, 20 Aug 2015 17:40:11 GMT|user-agent: nodejs httpSigClient.js",
        "computedSignature" : "",
        "error" : ""
      }
    }


### Example 7: create and send an RSA signature and trigger a verification error

    node ./httpSigClient.js \
     -a rsa-sha256 \
     -k CONSUMER_KEY_HERE \
     -p keys/key2-private.pem  \
     -o ORG_NAME_HERE  -t rsa-t5

This one tells the client to use RSA-sha256, with the private key as specified with the -p option. It sends the request to the /rsa-t5 path on the example API Proxy.

The Verification policy attached to the rsa-t5 path checks for RSA-sha1.  The verification will then fail, with a message like so:

```
{
  "error" : "algorithm used in signature (rsa-sha256) is not as required (rsa-sha1)"
}
```



### Example 8: create and send an RSA signature using rsa-sha1

```
node ./httpSigClient.js \
  -a rsa-sha1 \
  -k CONSUMER_KEY_HERE \
  -p keys/key2-private.pem  \
  -o ORG_NAME_HERE  -t rsa-t5
```

This is like Example 5, but the client uses rsa-sha1.

The Verification policy attached to the rsa-t5 path checks for RSA-sha1.  The verification will then succeed, with a message like so:

```
{
  "app.name" : "HttpSigApp",
  "apiproduct.name" : "HttpSigProduct",
  "signature" : {
    "keyId" : "CONSUMER_KEY_HERE",
    "algorithm" : "rsa-sha1",
    "headers" : "(request-target) date user-agent"
  },
  "verification": {
    "isValid" : "true",
    "requiredAlgorithm" : "rsa-sha1",
    "requiredHeaders" : "date (request-target)",
    "timeskew" : "1",
    "signingBase" : "(request-target): get /httpsig/rsa-t5?how=areyou|date: Thu, 20 Aug 2015 17:43:20 GMT|user-agent: nodejs httpSigClient.js",
    "computedSignature" : "",
    "error" : ""
  }
}
```

### Example 9: RSA, test missing header

```
node ./httpSigClient.js \
 -a rsa-sha256 \
 -k CONSUMER_KEY_HERE \
 -p keys/key2-private.pem  \
 -o ORG_NAME_HERE  -t rsa-t3
```

This one tells the lient to use RSA-sha256, with the private key as specified with the -p option. It sends the request to the /rsa-t3 path on the example API Proxy.

The Verify policy attached to the rsa-t3 flow checks for the presence of the nonce header in the signature. This client invocation does not send such a header, therefore the verification will fail.

You will see a message like so:

```json
{
  "error" : "signature is missing required header (nonce)."
}
```


### Example 10: send the nonce header

```
node ./httpSigClient.js \
   -a rsa-sha256 \
   -n 12345 \
   -k CONSUMER_KEY_HERE \
   -p keys/key2-private.pem  \
   -o ORG_NAME_HERE  -t rsa-t3
```

This one is like Example 7,  but the client actually sends the required nonce header and includes that header in the signature.

The Verify policy attached to the rsa-t3 flow checks for the presence of the nonce header in the signature. The verification will succeed.

You will see a message like so:

```json
{
  "app.name" : "HttpSigApp",
  "apiproduct.name" : "HttpSigProduct",
  "signature" : {
    "keyId" : "CONSUMER_KEY_HERE",
    "algorithm" : "rsa-sha256",
    "headers" : "(request-target) date user-agent nonce"
  },
  "verification": {
    "isValid" : "true",
    "requiredAlgorithm" : "",
    "requiredHeaders" : "date (request-target) nonce",
    "timeskew" : "0",
    "signingBase" : "(request-target): get /httpsig/rsa-t3?how=areyou|date: Thu, 20 Aug 2015 17:47:57 GMT|user-agent: nodejs httpSigClient.js|nonce: 12345",
    "computedSignature" : "",
    "error" : ""
  }
}
```


If you then send the same request again, using the same nonce, you will see an error:

```
{
  "error" : "re-used nonce."
}
```

The nonce cache in the apiproxy has a TTL of 86400 seconds, or one day.
