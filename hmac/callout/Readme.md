# HMAC Callout

This directory contains the Java source code required to compile a Java callout
for Apigee Edge that does [HMAC](https://en.wikipedia.org/wiki/HMAC) generation.

You do not need to build the code to use this callout; a usable JAR files is
available. But if you want to build, you can do so. See the section below on
Building.

## Usage Notes

There is a single class - HmacCreatorCallout - which calculates an HMAC on a payload.

Configure it like so:

```xml
<JavaCallout name='JavaCallout-HMAC-Create' enabled='true'>
  <DisplayName>JavaCallout-HMAC-Create</DisplayName>
  <Properties>
    <!-- name of the variable that holds the key -->
    <Property name="secret-key">{request.queryparam.key}</Property>
    <Property name="algorithm">sha-256</Property>
    <Property name="string-to-sign">{request.content}</Property>
  </Properties>
  <FaultRules/>
  <ClassName>com.apigee.callout.hmac.HmacCreatorCallout</ClassName>
  <ResourceURL>java://apigee-hmac-callout-20200407.jar</ResourceURL>
</JavaCallout>
```

The supported properties are:

| element             | purpose                                                                                                          |
|---------------------|------------------------------------------------------------------------------------------------------------------|
| algorithm           | One of: sha-1, sha1, sha-224, sha224, sha-256, sha256, sha-384, sha-256, md5, md-5.  Default: sha256             |
| secret-key          | The key material. By default this is decoded as a UTF-8 encoded string.                                          |
| secret-key-encoding | The key encoding. Supported: base16, hex, base64, base64url, utf-8. By default, utf-8.                                      |
| string-to-sign      | the string to sign with the key.                                                                                 |

The callout emits these variables into the message context:

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
    <Property name="secret-key">{request.queryparam.key}</Property>
    <Property name="algorithm">sha-256</Property>
    <Property name="string-to-sign">{request.header.date}|{request.verb}|{request.header.host}|{message.uri}</Property>
    <Property name="debug">false</Property>
  </Properties>
  <FaultRules/>
  <ClassName>com.apigee.callout.hmac.HmacCreatorCallout</ClassName>
  <ResourceURL>java://apigee-hmac-callout-20200407.jar</ResourceURL>
</JavaCallout>
```

In this case, the policy will resolve each of the variables surrounded by curlies and assign the resulting concatenation to string-to-sign.


## Validating Hmac

You can configure the policy to validate an hmac as well, by including the property named "hmac-base64" in the configuration. Like this:

```xml
<JavaCallout name='JavaCallout-HMAC-Validate' enabled='true'>
  <DisplayName>JavaCallout-HMAC-Create</DisplayName>
  <Properties>
    <!-- name of the variable that holds the key -->
    <Property name="secret-key">{request.queryparam.key}</Property>
    <Property name="algorithm">sha-256</Property>
    <Property name="string-to-sign">{request.header.date}|{request.verb}|{request.header.host}|{message.uri}</Property>
    <Property name="hmac-base64">{request.header.hmac}</Property>
  </Properties>
  <FaultRules/>
  <ClassName>com.apigee.callout.hmac.HmacCreatorCallout</ClassName>
  <ResourceURL>java://apigee-hmac-callout-20200407.jar</ResourceURL>
</JavaCallout>
```

The policy will raise a fault if the calculated hmac does not match the
provided hmac.  In fault rules, you can test hmac.error :

```xml
  <FaultRules>
    <FaultRule name='rule1'>
      <Step><Name>AssignMessage-HmacError</Name></Step>
      <Condition>hmac.error != null</Condition>
    </FaultRule>
  </FaultRules>
```

## Building The Code

You do not need to build the code to use this callout. But if you want to, you can do so.

1. unpack (if you can read this, you've already done that).

2. obtain the apigee pre-reqs.
   ```
    ./buildsetup.sh
   ```

   You must have maven installed in order for the above step to succeed.

2. build with maven:  `mvn clean package`

3. copy target/apigee-hmac-callout-20200407.jar to your apiproxy/resources/java directory

4. be sure to include a Java callout policy in your
   apiproxy/resources/policies directory. It should look like
   this:
   ```xml
    <JavaCallout name="JavaHmacHandler" enabled='true'
                 continueOnError='false' async='false'>
      <DisplayName>Java HMAC Creator</DisplayName>
      <Properties>...</Properties>
      <ClassName>com.apigee.callout.hmac.HmacCreatorCallout</ClassName>
      <ResourceURL>java://apigee-hmac-callout-20200407.jar</ResourceURL>
    </JavaCallout>
   ```

5. import and deploy with a tool like [importAndDeploy.js](https://github.com/DinoChiesa/apigee-edge-js-examples/blob/master/importAndDeploy.js)
or similar. Or, zip up the directory and use the Edge UI to import and deploy.



## Dependencies

- Apigee Edge expressions v1.0
- Apigee Edge message-flow v1.0
- Google Guava 26.0

All these jars must be available on the classpath for the compile to
succeed. The maven build will download all of these files for
you, automatically. At runtime all of these dependencies will be available
within Apigee.


## Unit tests

To run the unit tests, use maven:

```
mvn clean test
```
