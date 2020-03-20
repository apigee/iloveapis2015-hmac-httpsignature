httpsig
==================

This API proxy verifies an HTTP Signature.  It is a loopback proxy; it always
returns 200.  It provides a message payload that indicates an error if the
signature is invalid, or no error if the signature is valid.

The proposed standard for the HTTP Signature is [here](http://tools.ietf.org/html/draft-cavage-http-signatures-05).

Here's a summary of the spec:

The client sends in a Signature header that contains:
* keyid - identifying the key used by the client. The meaning is app dependent.
* algorithm - can be RSA-SHA (public/private key) or HMAC-SHA (with shared key)
* list of HTTP headers - optional; space delimited; these are included in the signing base
* a signature

Each element is formed as key="value" and they are separated by commas. This must be passed in an HTTP header named "Signature".
The resulting header might look like this:

```
Signature: keyId="Test",
algorithm="hmac-sha256",
headers="(request-target) date",
signature="udvCIHZAafyK+szbOI/KkLxeIihexHpHpvMrwbeoErI="
```

(line feeds have been added to the above for readability. In actuality, a
signature will be a single line with no intervening whitepace after the commas)

The actual signature is computed over a signing base which consists of a
concatenation of lines, separated by a newline character. Each line is a
lowercased header name, a colon, a space, and the header value. The order of the
headers in the signing base is as specified in the list. The signing base is not
transmitted to the server as part of the request.

In the list of headers, the value of (request-target) is treated specially: it
implies a string containing the (lowercased) request method and the URL
path+query, separated by a space. Therefore for the above authorization header,
the signing base might be:

```
(request-target): get /happy?when=now\ndate: Fri, 17 Jul 2015 17:55:56 GMT
```
Making a signed request from curl might look like this:

```
curl -i -X GET \
  -H "Date:  Fri, 17 Jul 2015 17:55:56 GMT" \
  -H 'Signature: keyId="Test",
          algorithm="hmac-sha256",
          headers="(request-target) date",
          signature="udvCIHZAafyK+szbOI/KkLxeIihexHpHpvMrwbeoErI="'  \
  https://deecee-test.apigee.net/httpsig/t1
```

(again, line feeds have been added to the Signature header shown above for
readability. In actuality, a signature will be a single line with no intervening
whitepace after the commas)

This looks simple, and it is. The only tricky part is computing the value of the
signature.

The server of such a request can verify the signature and reject a
request for which the signature is invalid.  This provides a way for the
server to authenticate the client, and verify the integrity of the
request.

-----

This API proxy receives the signature, then verifies it.  If HMAC, it
verifies by re-computing the signature based on the headers the server
has received, and comparing the computed sig with the received sig.  If
RSA, it verifies the signature by decrypting with the public key.

The verification is done in two phases: parse + verify.  Both are done
in Java, for performance reasons. It's possible to also do this in
Javascript, but it's faster in Java.

This proxy handles signatures with either RSA or HMAC algorithms. When
verifying an RSA signature, it interprets keyID as client_id and reads a
"custom attribute" attached to the developer app named public_key to get
the PEM-encoded public key. This means the client needs to compute its
signature using the corresponding private key, which it does not share
with the api proxy.  When verifying an HMAC signature, this proxy uses
the keyId to lookup the consumer secret, which it uses as the shared
secret for encryption.

To invoke the apiproxy, you need to compute the signature according to
the spec.  There's a [companion client](../client)  for this proxy written in nodejs
that depends on the node http-signature modile.


To aid in doing so, use the client application in the


## Resources:

* /rsa-t1
* /rsa-t2
* /rsa-t3
* /rsa-t4
* /rsa-t5
* /rsa-t6
* /hmac-t1
* /hmac-t2
* /hmac-t3
* /hmac-t4

You will invoke each resource with a request like:

```
  GET /httpsig/rsa-t1
  GET /httpsig/rsa-t2
   ...
  GET /httpsig/hmac-t1
   ...

```

But, remember, to send the requests, you need to compute an http signature header.
To aid in doing so, use the client application in the [client sibling directory](../client) here.


## Notes:

There is some setup required before you can use this API proxy.

1. This apiproxy must be included in an API Product. The proxy calls
   VerifyAPIKey using the keyId passed in the Signature header as the
   client_id. Upon success, it retrieves metadata attached to the
   developer app and uses it for verifying the signature.  For HMAC
   algorithms, the proxy uses the client_secret (aka consumer_secret) as
   the secret key.  For RSA algorithms, the proxy uses the custom
   attribute named "public_key".

   This means you must configure a developer app, which has access to the
   API product. When you invoke the API with the node client, specify the
   client id and client secret that is provisioned for the developer app.

2. You also need to create a cache called "cache1" in your environment before
   deploying this api proxy.

3. finally, To invoke the APIs in this proxy, you will need to use an
   intelligent client, something that can compute and transmit http
   signatures. The accompanying httpSigClient.js file (See the client directory)
   will do so.  You can also write your own client using any other language.


## Bugs:

* This proxy does not implement the WWW-Authenticate response with a
  configurable set of headers to sign.
