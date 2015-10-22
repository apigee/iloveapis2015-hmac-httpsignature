# HMAC

This directory contains Java source code for a callout which produces HMAC,
as well as an example API proxy, which shows how to use the callout. 


- [Java source](callout) - Java code, as well as instructions for how to build the Java code.
- [apiproxy](apiproxy) - an example API Proxy for Apigee Edge that shows how to use the resulting Java callout.


The API Proxy subdirectory here includes the pre-built JAR file. Therefore you do not need to build the Java code in order to use this JWT verifier. However, you may wish to modify this code for your own purposes. In that case, you will modify the Java code, re-build, then copy that JAR into the appropriate apiproxy/resources/java directory for the API Proxy. 


## Usage 

An HMAC is just a keyed MAC. It basically uses a shared key, also known s a secret key, embedded into the HMAC algorithm to produce a message authentication code (MAC) or hash.  the hash can then be verified by another party who also knows the secret key. 

Within the context of an API Proxy running in Apigee Edge, the HMAC is typically calculated using the consumer_secret of the client app.  Whether your API proxy uses oauth tokens or API key security, the consumer secret can act as the shared secret between the client app and the Edge proxy server. 

To demonstrate this, you will need to have the hmac API Proxy configured within an API 
Product in Edge, and you will need a developer app that is authorized to access the product. The developer app implies the client_id and client_secret keypair (Also sometimes known as consumer id and consumer secret). 

Normally this is done manually, but there's a script here that will do the job.  Run it like this: 

```
./provisionApiProductAndApp.sh -u USERNAME:PASSWORD -o ORGNAME -d 
```


After you run that command, you can use the client.sh script to send a payload with an HMAC. 

Example: 

```
$ ./client.sh -o iloveapis2015 -e test -k QihwaKOLFwqSVC6lMD1FwDDczWdrNF3E -s fGyarq3GOMDQQUL4 

This script invokes the hmac API Proxy.
==============================================================================

GLQEArvz/u2CTp92K0EvEQjE1niyoGdCW5mWPNaLHWo=
curl -i -X POST \
-d Four score and seven years ago our fathers brought forth on this continent, a new nation, conceived in Liberty, and dedicated to the proposition that all men are created equal. \
-H apikey: QihwaKOLFwqSVC6lMD1FwDDczWdrNF3E \
-H hmac-base64: OEDaMpM9WHRWHnwjucxF3L9xTRDl/I44bKa/0b/AxMA= \
http://iloveapis2015-test.apigee.net/hmac/with-apikey
HTTP/1.1 200 OK
Host: iloveapis2015-test.apigee.net
apikey: QihwaKOLFwqSVC6lMD1FwDDczWdrNF3E
hmac-base64: OEDaMpM9WHRWHnwjucxF3L9xTRDl/I44bKa/0b/AxMA=
Content-Length: 406
Content-Type: text/plain
Connection: keep-alive

key: fGyarq3GOMDQQUL4
string-to-sign: Four score and seven years ago our fathers brought forth on this continent, a new nation, conceived in Liberty, and dedicated to the proposition that all men are created equal.
algorithm: sha-256
javaized algorithm: HmacSHA256
signature-hex: 3840da32933d5874561e7c23b9cc45dcbf714d10e5fc8e386ca6bfd1bfc0c4c0
signature-b64: OEDaMpM9WHRWHnwjucxF3L9xTRDl/I44bKa/0b/AxMA=

```


The client uses the openssl tool to compute the HMAC on the client side. The client then transmit the payload, the hmac, and the API key in a request to the API Proxy.  The Proxy uses the API Key to lookup the consumer secret. It then computes the HMAC, and compares the computed HMAC against the client-provided HMAC value. 


The following example shows what happens when the client uses a different key than that used on the server:


```
$ ./client.sh -o iloveapis2015 -e test -k QihwaKOLFwqSVC6lMD1FwDDczWdrNF3E -s WRONG_KEY 

This script invokes the hmac API Proxy.
==============================================================================

GLQEArvz/u2CTp92K0EvEQjE1niyoGdCW5mWPNaLHWo=
curl -i -X POST \
-d Four score and seven years ago our fathers brought forth on this continent, a new nation, conceived in Liberty, and dedicated to the proposition that all men are created equal. \
-H apikey: QihwaKOLFwqSVC6lMD1FwDDczWdrNF3E \
-H hmac-base64: fTOKxt/Kz2h5AelsoD37h8/ePDvMJCny5JBG68ty++U= \
http://iloveapis2015-test.apigee.net/hmac/with-apikey
HTTP/1.1 400 OK
Content-Type: text/plain
Content-Length: 30
Connection: keep-alive


error: HMAC does not verify
```