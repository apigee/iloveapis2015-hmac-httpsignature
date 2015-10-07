## HMAC Callout

This directory contains the Java source code and Java jars required to
compile a Java callout for Apigee Edge that does HMAC generation.

Building The Code
----------------

1. unpack (if you can read this, you've already done that).

2. You can build one of two ways, with the bash script or with maven.  
   With script:  ./build.sh  
   With maven:  mvn clean package

3. copy target/hmac-edge-callout.jar to your apiproxy/resources/java directory

4. be sure to include a Java callout policy in your
   apiproxy/resources/policies directory. It should look like
   this:

    <JavaCallout name="JavaHmacHandler" enabled='true'
                 continueOnError='false' async='false'>
      <DisplayName>Java HMAC Creator</DisplayName>
      <Properties>...</Properties>
      <ClassName>com.apigee.callout.hmac.HmacCreatorCallout</ClassName>
      <ResourceURL>java://hmac-edge-callout.jar</ResourceURL>
    </JavaCallout>

5. pushapi (See https://github.com/carloseberhardt/apiploy)



Dependencies
------------------

Apigee Edge expressions v1.0
Apigee Edge message-flow v1.0
Apache commons codec v1.7


All these jars must be available on the classpath for the compile to
succeed.  The build.sh script should download all of these files for
you, automatically.

If you want to download them manually: 

    The first 2 jars are available in Apigee Edge. The first two are
    produced by Apigee; contact Apigee support to obtain these jars to allow
    the compile, or get them here: 
    https://github.com/apigee/api-platform-samples/tree/master/doc-samples/java-cookbook/lib

    The Apache Commons Codec jar is shipped by the Apache Software
    Foundation. You should compile against v1.7, because that is what
    Apigee Edge currently uses.
    http://commons.apache.org/proper/commons-codec/

Notes:
--------

There is a single class - HmacCreatorCallout - which calculates an HMAC on a payload.

Configure it like so:

```xml
<JavaCallout name='JavaCallout-HMAC-Create' enabled='true'>
  <DisplayName>JavaCallout-HMAC-Create</DisplayName>
  <Properties>
    <!-- name of the variable that holds the key -->
    <Property name="key">{request.queryparam.key}</Property>
    <Property name="algorithm">sha-256</Property>
    <Property name="string-to-sign">{request.content}</Property>
    <Property name="debug">false</Property>
  </Properties>
  <FaultRules/>
  <ClassName>com.apigee.callout.hmac.HmacCreatorCallout</ClassName>
  <ResourceURL>java://hmac-edge-callout.jar</ResourceURL>
</JavaCallout>
```

NB: valid algorithm arguments are: 
  sha-1, sha1, sha-224, sha224, sha-256, sha256, sha-384, sha-256

The algorithm can be specified in any case. 


The callout emits these variables into the message context:

- hmac.key - string form of the key used in signing (only if debug property is set true)
- hmac.string-to-sign - the message being signed
- hmac.alg - the algorithm
- hmac.signature.hex - the signed hash, hex encoded.
- hmac.signature.b64 - the signed hash, base64 encoded.

This policy can be used to generate HMACs for outbound calls, or to verify HMACs for inbound calls. 

If you omit the "string-to-sign" property, the policy will default to computing an HMAC on the message.content. 


You can also use a string-to-sign that concatenates the values of 
several variables and static strings, like this:


```xml
<JavaCallout name='JavaCallout-HMAC-Create' enabled='true'>
  <DisplayName>JavaCallout-HMAC-Create</DisplayName>
  <Properties>
    <!-- name of the variable that holds the key -->
    <Property name="key">{request.queryparam.key}</Property>
    <Property name="algorithm">sha-256</Property>
    <Property name="string-to-sign">{request.header.date}|{request.verb}|{request.url}</Property>
    <Property name="debug">false</Property>
  </Properties>
  <FaultRules/>
  <ClassName>com.apigee.callout.hmac.HmacCreatorCallout</ClassName>
  <ResourceURL>java://hmac-edge-callout.jar</ResourceURL>
</JavaCallout>
```

In this case, the policy will resolve each of the variables surrounded by curlies and assign the resulting concatenation to string-to-sign. 
