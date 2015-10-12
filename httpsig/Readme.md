# HttpSignature

This directory contains Java source code for a callout which verifies HttpSignature
as well as an example API proxy, which shows how to use the callout. Finally, it also includes an intelligent client  that computes HttpSignatures and sends out requests to the API proxy.  


- [Java source](callout) - Java code, as well as instructions for how to build the Java code.
- [apiproxy](apiproxy) - an example API Proxy for Apigee Edge that shows how to use the resulting Java callout.
- [client](client) - a test client that sends API requests that contain HttpSignatures. 


The API Proxy subdirectory here includes the pre-built JAR file. Therefore you do not need to build the Java code in order to use this JWT verifier. However, you may wish to modify this code for your own purposes. In that case, you will modify the Java code, re-build, then copy that JAR into the appropriate apiproxy/resources/java directory for the API Proxy. 
