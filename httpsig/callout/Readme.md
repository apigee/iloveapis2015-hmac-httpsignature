## HttpSignature verifier

This directory contains the Java source code and Java jars required to
compile a Java callout for Apigee Edge that does Verification of HTTP
Signatures, either RSA or HMAC.

HTTP Signature is a [draft specification for an IETF standard](https://tools.ietf.org/html/draft-cavage-http-signatures-10).

It describes how to generate and verify signatures on HTTP requests. This specification has been in draft status since at least 2015, and it's not clear that it will move to final standardization and "recommendation" status. Even so, it's stable and it works.

## Disclaimer

This example is not an official Google product, nor is it part of an official Google product.

## Quick Overview of HTTP Signature

The spec describes how to sign a set of HTTP headers in a request.
According to the specification, an HTTP signature looks like this:

Signature: keyId="mykey",algorithm="hmac-sha256",headers="(request-target) date",signature="udvCIHZAafyK+szbOI/KkLxeIihexHpHpvMrwbeoErI="

These are the elements:

| element     | purpose |
|-------------|------------------------------------------------|
| keyId       | identify the key used to produce the signature |
| algorithm   | the algorithm used to produce the sig. Supported mechanisms include hmac-sha256 and rsa-sha256.  |
| headers     | the set of headers which has been signed. This element is optional, according to the spec.  |
| signature   | the base64-encoded signature value.            |

Receivers of an HTTP request bearing a signature can lookup a key from the asserted keyId, and then verify the asserted signature on the set of headers. If the signature is valid, then the receiver can be assured the request has not been modified in transit.


## Building the Code

You do not need to build the code to use this callout. But if you want to, you can do so.

1. unpack (if you can read this, you've already done that).

2. obtain the apigee pre-reqs.
   ```
    ./buildsetup.sh
   ```

   You must have maven installed in order for the above step to succeed.

3. run the build:
   ```
    mvn clean package
   ```

   The above step will also run the included tests.

After building the code, copy the resulting jar file, available in
target/edge-custom-httpsig-1.0.2.jar to your apiproxy/resources/java
directory, or upload the jar to a resource in your org, env, or proxy.


## Dependencies

- Apigee Edge expressions v1.0
- Apigee Edge message-flow v1.0
- Google Guava 26.0-jre



## Using the callout

You must use the callout in two phases: parse and verify. The parse phase
extracts the elements from the signature header. The verify phase actually
verifies the extracted signature. These are separate phases to allow the API
proxy to use the output of the parse phase, specifically the keyId, to retrieve
a key from whatever store is appropriate.  Only after the parse can the proxy
know the key to use for verification. So the logic works like this:

1. parse the signature header to determine the keyId
2. retrieve the key
3. verify the signature with the retrieved key

Therefore you must Include TWO Java callout policies in your
apiproxy/resources/policies directory. The first does the parsing, the second
performs the signature validation and verification.

The first policy should be configured like this:
```xml
  <JavaCallout name='Java-ParseHttpSignature'>
    <Properties/>
    <ClassName>com.google.apigee.callout.httpsignature.SignatureParserCallout</ClassName>
    <ResourceURL>java://edge-custom-httpsig-1.0.2.jar</ResourceURL>
  </JavaCallout>
```


The second should look something like this:
```xml
  <JavaCallout name='Java-VerifyHttpSignature1'>
    <Properties>
      <Property name='public-key'>{verifyapikey.VerifyApiKey-1.public_key}</Property>
      <Property name='headers'>date (request-target)</Property>
    </Properties>
    <ClassName>com.google.apigee.callout.httpsignature.SignatureVerifierCallout</ClassName>
    <ResourceURL>java://edge-custom-httpsig-1.0.2.jar</ResourceURL>
  </JavaCallout>
```

After including those policies in your proxy, use the Edge UI, or a command-line
tool like [importAndDeploy.js](https://github.com/DinoChiesa/apigee-edge-js/blob/master/examples/importAndDeploy.js)
or similar to import the proxy into an Edge organization, and then deploy the
proxy.

Then, use a client to generate and send http requests with appropriate HTTP
Signatures, to the proxy.



## Notes

There is one callout class, com.google.apigee.callout.httpsignature.SignatureParserCallout ,
which parses an HTTP Signature .  There is another, com.google.apigee.callout.httpsignature.SignatureVerifierCallout , that verifies the HTTP signature.

The reason this is done in two separate steps is that sometimes the configuration of the Verification step requires data which can be retrieved only after the signature has been parsed. Doing the parse and verify in one callout would prevent retrieval of secvret keys or public keys from the developer app entity, for example.

You must configure each callout with Property elements in the policy
configuration.

Examples for how to parse and verify an HTTP signature using HMAC-sha256 follow.

To get the signature example to work, you will need the API Proxy to be created. You also need an API Product, which must contain the API Proxy.  And you also need a Developer app, with a client_id and client_secret (aka consumer id and consumer secret).

In the examples that follow, the consumer secret will be used as the
shared secret for HMAC encryption. This is not required; in fact you can
use any shared secret key.  But it is probably a good standard practice
to use the consumer secret as the shared secret.

If you wish to use RSA encryption, then you will need to separately generate an RSA keypair, use the private key on the client, and make the public key available to the Proxy in some way. The easiest way is to attach a custom attribute, call it public_key, to a developer app, and place the PEM-encoded public key there.


## Example 1: Parse the signature

We want to parse the signature because the keyId contained within the signature may indicate which public key to retrieve, for use during stage 2, signature verification.

```xml
<JavaCallout name='Java-ParseHttpSignature'>
  <ClassName>com.google.apigee.callout.httpsignature.SignatureParserCallout</ClassName>
  <ResourceURL>java://edge-custom-httpsig-1.0.2.jar</ResourceURL>
</JavaCallout>
```

The result of the parse step is to extract the components of
the signature as passed in, and set context variables in Edge, like so:

- httpsig_algorithm
- httpsig_keyId
- httpsig_signature
- httpsig_headers

These context variables are then available to subsequent logic steps in
the proxy flow. This is useful if, for example, the keyId provides some
indication of which public key or secret key to use for signature
verification. For example if the keyId is an API Key, and a public key
or secret key is attached to the developer app, then the flow steps will
be ParseSignature, VerifyApiKey, VerifySignature.

By default the Parse policy retrieves the signature from the Signature HTTP header. If you wish to parse a signature that is not available in request.header.signature, then use the following configuration:

```xml
<JavaCallout name='Java-ParseHttpSignature'>
  <Properties>
    <Property name='fullsignature'>{context.variable.containing.sig}</Property>
  </Properties>
  <ClassName>com.google.apigee.callout.httpsignature.SignatureParserCallout</ClassName>
  <ResourceURL>java://edge-custom-httpsig-1.0.2.jar</ResourceURL>
</JavaCallout>
```

This Parse step with set the context variable parse_error to a non-empty
value if the signature is not well formed: if it lacks a required key,
or if they values are not specified in quotes, if the algorithm
specified is invalid, and so on. The Parse step does no validation of
the signature.


The second Java callout class performs the verification:

```xml
<JavaCallout name='Java-VerifyHttpSignature1'>
  <Properties>
    <Property name='algorithm'>rsa-sha256</Property>
    <Property name='public-key'>{verifyapikey.VerifyApiKey-1.public_key}</Property>
  </Properties>
  <ClassName>com.google.apigee.callout.httpsignature.SignatureVerifierCallout</ClassName>
  <ResourceURL>java://edge-custom-httpsig-1.0.2.jar</ResourceURL>
</JavaCallout>
```

Of course you can use whatever name attribute on the policy you like.
The ClassName must be as shown.

The policy uses the varprefix to name the variables which it sets.
The verify callout sets at least these context variables:

    httpsig_isValid - true/false, telling whether the
            signature is valid and complies with the requirements (headers and algorithm).

    httpsig_error - set only when there is an error, contains the exception.

The callout also sets other context variables. Examine the Edge trace window at runtime for the full list.


The above example shows how to verify an RSA-based signature with the
given public key. The public-key can be specified as a string or a
variable to de-reference if enclosed in curly-braces. The latter is
shown above. In this example the public key was attached as a custom
attribute to a developer app, and the policy was preceded by the use of
a VerifyApiKey policy. This variable must contain something like the
following:

```
  -----BEGIN PUBLIC KEY-----
  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtxlohiBDbI/jejs5WLKe
  Vpb4SCNM9puY+poGkgMkurPRAUROvjCUYm2g9vXiFQl+ZKfZ2BolfnEYIXXVJjUm
  zzaX9lBnYK/v9GQz1i2zrxOnSRfhhYEb7F8tvvKWMChK3tArrOXUDdOp2YUZBY2b
  sl1iBDkc5ul/UgtjhHntA0r2FcUE4kEj2lwU1di9EzJv7sdE/YKPrPtFoNoxmthI
  OvvEC45QxfNJ6OwpqgSOyKFwE230x8UPKmgGDQmED3PNrio3PlcM0XONDtgBewL0
  3+OgERo/6JcZbs4CtORrpPxpJd6kvBiDgG07pUxMNKC2EbQGxkXer4bvlyqLiVzt
  bwIDAQAB
  -----END PUBLIC KEY-----
```

The public-key property accepts RSA keys only, in either PKCS#8 or PKCS#1
format. (Base64-encoded, wrapped in the ----BEGIN ---- and -----END--- lines.)

The above configuration simply verifies that a signature is present. It does not enforce a particular algorithm, or verify that a specific set of headers is present in the signature. To do that, you need to use a configuration like this:

```xml
<JavaCallout name='Java-VerifyHttpSignature4'>
  <Properties>
    <Property name='public-key'>{verifyapikey.VerifyApiKey-1.public_key}</Property>
    <Property name='headers'>date (request-target)</Property>
    <Property name='algorithm'>rsa-sha256</Property>
    <Property name='maxtimeskew'>120</Property>
  </Properties>
  <ClassName>com.google.apigee.callout.httpsignature.SignatureVerifierCallout</ClassName>
  <ResourceURL>java://edge-custom-httpsig-1.0.2.jar</ResourceURL>
</JavaCallout>
```

The algorithm property is optional. If specified, this is the algorithm
that must be used on the inbound signature. Valid values here, when
using public/private key encryption, are rsa-sha1, rsa-sha256, and
rsa-sha512.

The headers property is also optional. If specified, it must be a
space-delimited set of names. The policy enforces that the inbound
signature includes AT LEAST those headers listed in the value, in any
order. The inbound signature may include other headers in the signature
beyond those required here. The list of headers should be
space-delimited as shown here. If there is no headers property, then the
policy does not enforce a specific set of headers to be contained in the
signature. This is not recommended.

The maxtimeskew property is optional. If specified, this is the maximum
difference in seconds that will be allowed between the time stamped on
the request in the Date header, and the actual time on the proxy
server. If this value is zero or less, no maximum time skew is
enforced. If the value is not present, it defaults to 60 seconds. In
other words, a request with a Date header that represents a time of more
than 60 seconds ago, or more than 60 seconds in the future, will be
rejected. If the request has no Date header, then this skew is not
enforced. The maxtimeskew works best when accompanied by a Property
that indicates the Date header is required to be included in the
signature.

The verify policy extracts the signature from the default location - the
Signature header on the request. If it is present elsewhere, you need to
specify it with the fullsignature property, as in the example for
Parsing a signature.


## Example 2

```xml
<JavaCallout name='Java-VerifyHttpSignature4'>
  <Properties>
    <Property name='public-key'>
      -----BEGIN PUBLIC KEY-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtxlohiBDbI/jejs5WLKe
      Vpb4SCNM9puY+poGkgMkurPRAUROvjCUYm2g9vXiFQl+ZKfZ2BolfnEYIXXVJjUm
      zzaX9lBnYK/v9GQz1i2zrxOnSRfhhYEb7F8tvvKWMChK3tArrOXUDdOp2YUZBY2b
      sl1iBDkc5ul/UgtjhHntA0r2FcUE4kEj2lwU1di9EzJv7sdE/YKPrPtFoNoxmthI
      OvvEC45QxfNJ6OwpqgSOyKFwE230x8UPKmgGDQmED3PNrio3PlcM0XONDtgBewL0
      3+OgERo/6JcZbs4CtORrpPxpJd6kvBiDgG07pUxMNKC2EbQGxkXer4bvlyqLiVzt
      bwIDAQAB
      -----END PUBLIC KEY-----
    </Property>
    <Property name='headers'>date (request-target)</Property>
    <Property name='algorithm'>rsa-sha256</Property>
  </Properties>
  <ClassName>com.google.apigee.callout.httpsignature.SignatureVerifierCallout</ClassName>
  <ResourceURL>java://edge-custom-httpsig-1.0.2.jar</ResourceURL>
</JavaCallout>
```

The above example shows how to specify the public key in PEM format
directly in the policy configuration file. The configuration accepts RSA
keys only, in either PKCS#8 or PKCS#1 format. Base64-encoded.


## Example 3

```xml
<JavaCallout name='Java-VerifyHttpSignature'>
  <Properties>
    <Property name='pemfile'>publickey-1.pem</Property>
    <Property name='algorithm'>rsa-sha256</Property>
    <Property name='headers'>Date (request-target)</Property>
  </Properties>
  <ClassName>com.google.apigee.callout.httpsignature.SignatureVerifierCallout</ClassName>
  <ResourceURL>java://edge-custom-httpsig-1.0.2.jar</ResourceURL>
</JavaCallout>
```

In this exmple, the public key is retrieved from a resource that is
embedded into the JAR file itself.  This requires you to re-compile or
at least re-assemble the jar file. The structure of the jar must be like
so:

        meta-inf/
        meta-inf/manifest.mf
        com/
        com/dinochiesa/
        com/dinochiesa/httpsignature/SignatureVerifierCallout.class
        com/dinochiesa/httpsignature/SignatureParserCallout.class
        com/dinochiesa/httpsignature/HttpSignature.class
        resources/
        resources/publickey-1.pem

You can also specify the pemfile as a variable, inside curlies. It gets
resolved the same way - must be present as a resource in the
jar. (Because it requires re-assembling the jar file, this is probably a
much less convenient way to specify the public key, than just embedding
the PEM into the configuration file itself.)


## Example 4

```xml
<JavaCallout name='Java-VerifyHttpSignature'>
  <Properties>
    <Property name='fullsignature>{context.variable.here}</Property>
    <Property name='public-key'>{verifyapikey.VerifyApiKey-1.public_key}</Property>
    <Property name='algorithm'>rsa-sha256</Property>
    <Property name='headers'>Date (request-target)</Property>
  </Properties>
  <ClassName>com.google.apigee.callout.httpsignature.SignatureVerifierCallout</ClassName>
  <ResourceURL>java://edge-custom-httpsig-1.0.2.jar</ResourceURL>
</JavaCallout>
```

In this example, the policy retrieves the signature from the specified
location, rather than directly reading the Signature Header on the
request.



## Example 5

In addition to verifying signatures that are RSA-based, the callout call
also be used to verify a signature with an HMAC and a secret key. Here's
an example:

```xml
<JavaCallout name='Java-VerifyHttpSignature'>
  <Properties>
    <Property name='secret-key'>{verifyapikey.VerifyApiKey-1.client_secret}</Property>
    <Property name='algorithm'>hmac-sha256</Property>
    <Property name='headers'>Date (request-target)</Property>
  </Properties>
  <ClassName>com.google.apigee.callout.httpsignature.SignatureVerifierCallout</ClassName>
  <ResourceURL>java://edge-custom-httpsig-1.0.2.jar</ResourceURL>
</JavaCallout>
```

In this example, the policy verifies an HMAC signature, using the
client_secret from the designated app. Valid values for hmac algorithms
are: hmac-sha1, hmac-sha256, hmac-sha512.

The secret-key property is used only if the algorithm is an HMAC
algorithm. Do not specify a public-key property when verifying
signatures that use HMAC algorithms. Do not specify a secret-key
property when verifying signatures with RSA algorithms.



## Support

This callout is open-source software, and is not a supported part of Apigee Edge.
If you need assistance, you can try inquiring on
[The Apigee Community Site](https://community.apigee.com).  There is no service-level
guarantee for responses to inquiries regarding this callout.

## License

This material is copyright 2015,2016 Apigee Corporation, 2017-2018 Google LLC.
and is licensed under the [Apache 2.0 License](LICENSE). This includes the Java
code as well as the API Proxy configuration.

## Known Bugs

?? none
