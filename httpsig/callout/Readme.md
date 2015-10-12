## HttpSignature verifier

This directory contains the Java source code and Java jars required to
compile a Java callout for Apigee Edge that does Verification of HTTP
Signatures, either RSA or HMAC.

HTTP Signature is a [draft specification for an IETF standard](http://tools.ietf.org/html/draft-cavage-http-signatures-05).


It describes how to generate and verify signatures on HTTP requests. 


Building the Code
--------------------

1. unpack (if you can read this, you've already done that).

2. run the build: 
```
 mvn clean package 
```

3. if you edit proxy bundles offline, copy the resulting jar file, available in  target/edgecallout-http-signature-verifier.jar to your apiproxy/resources/java directory.  If you don't edit proxy bundles offline, upload the jar file into the API Proxy via the Edge API Proxy Editor . 


4. include TWO Java callout policies in your
   apiproxy/resources/policies directory. The first does the parsing, the second 
   performs the signature validation and verification. The first should
   like this:  
   ```xml
    <JavaCallout name='Java-ParseHttpSignature'>
      <Properties/>
      <ClassName>com.apigee.callout.httpsignature.SignatureParserCallout</ClassName>
      <ResourceURL>java://edgecallout-http-signature-verifier.jar</ResourceURL>
    </JavaCallout>
   ```  
   The second should look like this:   
   ```xml
    <JavaCallout name='Java-VerifyHttpSignature1'>
      <Properties>
        <Property name='public-key'>{verifyapikey.VerifyApiKey-1.public_key}</Property>
      </Properties>
      <ClassName>com.apigee.callout.httpsignature.SignatureVerifierCallout</ClassName>
      <ResourceURL>java://edgecallout-http-signature-verifier.jar</ResourceURL>
    </JavaCallout>
   ```

5. use the Edge UI, or a command-line tool like pushapi (See
   https://github.com/carloseberhardt/apiploy) or similar to
   import the proxy into an Edge organization, and then deploy the proxy . 

6. Use a client to generate and send http requests with appropriate HTTP
Signatures, to the proxy. 



Dependencies
------------------

- Apigee Edge expressions v1.0
- Apigee Edge message-flow v1.0
- Apache commons lang 2.6
- Apache commons codec 1.7
- Apache commons httpclient 4.3.5

These jars must be available on the classpath for the compile to
succeed. The build.sh script should download all of these files for
you, automatically. You could also create a Gradle or maven pom file as
well. 

If you want to download them manually: 

  The first 2 jars are available in Apigee Edge. The first two are
  produced by Apigee; contact Apigee support to obtain these jars to allow
  the compile, or get them here: 
  https://github.com/apigee/api-platform-samples/tree/master/doc-samples/java-cookbook/lib

  The Apache jars are also all available in Apigee Edge at runtime. To download them for compile time, you can get them from maven.org. 



Notes
------

There is one callout class, com.apigee.callout.httpsignature.SignatureParserCallout ,
which parses an HTTP Signature .  There is another, com.apigee.callout.httpsignature.SignatureVerifierCallout , that verifies the HTTP signature. 

The reason this is done in two separate steps is that sometimes the configuration of the Verification step requires data which can be retrieved only after the signature has been parsed. Doing the parse and verify in one callout would prevent retrieval of secvret keys or public keys from the developer app entity, for example. 

You must configure each callout with Property elements in the policy
configuration.

Examples for how to parse and verify an HTTP signature follow. 

To get this all to work, you will need the API Proxy to be created. You also need an API Product, which must contain the API Proxy.  And you also need a Developer app, with a client_id and client_secret (aka consumer id and consumer secret).  

In the examples that follow, the consumer secret will be used as the
shared secret for HMAC encryption. This is not required; in fact you can
use any shared secret key.  But it is probably a good standard practice
to use the consumer secret as the shared secret.

If you wish to use RSA encryption, then you will need to separately generate an RSA keypair, use the private key on the client, and make the public key available to the Proxy in some way. The easiest way is to attach a custom attribute, call it public_key, to a developer app, and place the PEM-encoded public key there. 


## Example 1: Parse the signature

We want to parse the signature because the keyId contained within the signature may indicate which public key to retrieve, for use during stage 2, signature verification.

```xml
<JavaCallout name='Java-ParseHttpSignature'>
  <Properties>
    <Property name='varprefix'>parse</Property>
  </Properties>
  <ClassName>com.apigee.callout.httpsignature.SignatureParserCallout</ClassName>
  <ResourceURL>java://edgecallout-http-signature-verifier.jar</ResourceURL>
</JavaCallout>
```

The policy uses the varprefix to name the context variables which it
sets. It is optional; if you don't set it, it gets the value of
"httpsig". The result of the parse step is to extract the components of
the signature as passed in, and set context variables in Edge, like so:

- {prefix}_algorithm
- {prefix}_keyId
- {prefix}_signature
- {prefix}_headers

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
    <Property name='varprefix'>parse</Property>
    <Property name='fullsignature'>{flow.variable.containing.sig}</Property>
  </Properties>
  <ClassName>com.apigee.callout.httpsignature.SignatureParserCallout</ClassName>
  <ResourceURL>java://edgecallout-http-signature-verifier.jar</ResourceURL>
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
    <Property name='varprefix'>sig</Property>
    <Property name='algorithm'>rsa-sha256</Property>
    <Property name='public-key'>{verifyapikey.VerifyApiKey-1.public_key}</Property>
  </Properties>
  <ClassName>com.apigee.callout.httpsignature.SignatureVerifierCallout</ClassName>
  <ResourceURL>java://edgecallout-http-signature-verifier.jar</ResourceURL>
</JavaCallout>
```

Of course you can use whatever name attribute on the policy you like. 
The ClassName must be as shown. 

The policy uses the varprefix to name the variables which it sets.  
The verify callout sets at least these context variables: 

    <varprefix>_isValid - true/false, telling whether the
            signature is valid and complies with the requirements (headers and algorithm). 

    <varprefix>_error - set only when there is an error, contains the exception. 

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
    <Property name='varprefix'>sig</Property>
    <Property name='public-key'>{verifyapikey.VerifyApiKey-1.public_key}</Property>
    <Property name='headers'>date (request-target)</Property>
    <Property name='algorithm'>rsa-sha256</Property>
    <Property name='maxtimeskew'>120</Property>
  </Properties>
  <ClassName>com.apigee.callout.httpsignature.SignatureVerifierCallout</ClassName>
  <ResourceURL>java://edgecallout-http-signature-verifier.jar</ResourceURL>
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
    <Property name='varprefix'>sig</Property>
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
  <ClassName>com.apigee.callout.httpsignature.SignatureVerifierCallout</ClassName>
  <ResourceURL>java://edgecallout-http-signature-verifier.jar</ResourceURL>
</JavaCallout>
```

The above example shows how to specify the public key in PEM format
directly in the policy configuration file. The configuration accepts RSA
keys only, in either PKCS#8 or PKCS#1 format. Base64-encoded. 


## Example 3

```xml
<JavaCallout name='Java-VerifyHttpSignature'>
  <Properties>
    <Property name='varprefix'>sig</Property>
    <Property name='pemfile'>publickey-1.pem</Property>
    <Property name='algorithm'>rsa-sha256</Property>
    <Property name='headers'>Date (request-target)</Property>
  </Properties>
  <ClassName>com.apigee.callout.httpsignature.SignatureVerifierCallout</ClassName>
  <ResourceURL>java://edgecallout-http-signature-verifier.jar</ResourceURL>
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
    <Property name='varprefix'>sig</Property>
    <Property name='fullsignature>{context.variable.here}</Property>
    <Property name='public-key'>{verifyapikey.VerifyApiKey-1.public_key}</Property>
    <Property name='algorithm'>rsa-sha256</Property>
    <Property name='headers'>Date (request-target)</Property>
  </Properties>
  <ClassName>com.apigee.callout.httpsignature.SignatureVerifierCallout</ClassName>
  <ResourceURL>java://edgecallout-http-signature-verifier.jar</ResourceURL>
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
    <Property name='varprefix'>sig</Property>
    <Property name='secret-key'>{verifyapikey.VerifyApiKey-1.client_secret}</Property>
    <Property name='algorithm'>hmac-sha256</Property>
    <Property name='headers'>Date (request-target)</Property>
  </Properties>
  <ClassName>com.apigee.callout.httpsignature.SignatureVerifierCallout</ClassName>
  <ResourceURL>java://edgecallout-http-signature-verifier.jar</ResourceURL>
</JavaCallout>
```

In this example, the policy verifies an HMAC signature, using the
client_secret from the designated app. Valid values for hmac algorithms
are: hmac-sha1, hmac-sha256, hmac-sha512. 

The secret-key property is used only if the algorithm is an HMAC
algorithm. Do not specify a public-key property when verifying
signatures that use HMAC algorithms. Do not specify a secret-key
property when verifying signatures with RSA algorithms.


Bugs
--------

There are no unit tests for this project.
