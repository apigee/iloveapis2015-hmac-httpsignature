# I love APIs 2015 - Advanced Security Extensions - HMAC, HttpSignature

This repo contains all the source code, sample api proxies, readmes, and other supporting information for the session entitled "Advanced Security Extensions - HMAC, HttpSignature" at Apigee's ILoveAPIS 2015 conference, held in San Jose, California, 2015 October 12-14.


## What's going on here?

This repo contains Java source code for Apigee Edge callout classes, that do HMAC and HttpSignature.  You can build the Java callout classes and immediately begin using them in your API Proxies.

- [HMAC](hmac) - Generating HMACs within an Apigee Edge apiproxy
- [HttpSignature](httpsig) - Verifying HttpSignatures within an Apigee Edge apiproxy


## Pre-build step

It is not necessary to build the Java source code contained in the subdirectories here, in order to use the HMAC or HttpSignature policies in Apigee Edge.  But, if you do wish to build, to allow the maven builds to succeed, you need to first run the buildsetup.sh script on your workstation. This adds the Apigee-required jars into the local maven repository (your local cache).

Do this like so:

```
  ./buildsetup.sh
```

You must have maven installed in order for the above step to succeed.

After the buildsetup, to build the jars with maven, follow the usual
steps.  This is described in greater detail in the callout source
directory for each sudirectory here.
