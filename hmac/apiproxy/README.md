HMAC Example proxy
========================

This api proxy shows how to use a custom Java callout that calculates HMACs. 

What's an HMAC?  https://en.wikipedia.org/wiki/HMAC

Typically you'd use an HMAC to sign a message, or verify a signature on
a message.

Apigee Edge doesn't currently contain "built-in" capability to create or
calculate HMACs on arbitrary payloads. This proxy shows how to use a
Java callout to do that.  

You can take advantage of this callout without knowing Java and without
any additional coding. Just drop the policy into your API proxy and go.
This API Proxy demonstrates how you can do that. 


Invoking
========

There is just one request exposed by this proxy:

Generate an HMAC on a given payload using alg=sha-256, with key secret123: 

    curl -i -X POST -d 'the quick brown fox...' \
       "http://myorg-myenv.apigee.net/hmac/payload?alg=sha-256&key=secret123"

The response is plain text like this: 

```
key: secret123
stringToSign: the quick brown fox...
algorithm: sha-256
javaized algorithm: HmacSHA256
signature: bf41d260dacd49be2d09e7c80f0cb5614bce8997c7a371994daafd606a6c4e2f
```

You can also compute an HMAC on various headers and other values in the message: 

```
  curl -i -X POST -d '' \
   -H "Date:`date -u +'%a, %d %b %Y %H:%M:%S GMT'`" \
   "http://myorg-myenv.apigee.net/hmac/headers?alg=sha-256&key=secret123"
```

The incantation around the Date header just create an RFC-1123 compliant date value. The result of this call looks like this: 

```
key: secret123
string-to-sign: Wed, 07 Oct 2015 21:10:19 GMT|POST|iloveapis2015-test.apigee.net|/hmac/headers?alg=sha-256&key=secret123
algorithm: sha-256
javaized algorithm: HmacSHA256
signature-hex: 2d9af1e471d593854627afef4b83332f59cccc4d0e21b1392f239324e480abd6
signature-b64: LZrx5HHVk4VGJ6/vS4MzL1nMzE0OIbE5LyOTJOSAq9Y=

```

Finally, 
you can get help on this demonstration API Proxy like this: 

```
    curl -i -X GET  http://myorg-myenv.apigee.net/hmac
```



Usage Notes:
============

There are two ways to use this callout: for verification and for HMAC
creation.  Either way, it works the same: you will use the Java callout
to perform HMAC calculation.  For verification, you'd then compare the
result to the passed-in signature.  For signature creation, you'd send
the resulting signature in a message to the backend.




