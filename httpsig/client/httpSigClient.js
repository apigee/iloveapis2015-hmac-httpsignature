// httpSigClient.js
// ------------------------------------------------------------------
//
// A client that sends an http request containing an HTTP
// Signature that uses RSA signing, or HMAC signing.
//
// created: Mon Jul 20 11:11:32 2015
// last saved: <2020-March-23 13:32:16>
/* jshint esversion:9 */
/* global process */

const fs = require('fs'),
      http = require('http'),
      httpSignature = require('http-signature'),
      Getopt = require('node-getopt'),
      defaults = {path : 'rsa-t1', alg: 'rsa-sha256'},
      getopt = new Getopt([
      ['p' , 'privkey=ARG', 'PEM file for the private key. (only for RSA)'],
      ['s' , 'secretkey=ARG', 'secret key. (only for HMAC)'],
      ['o' , 'org=ARG', 'the Edge organization'],
      ['e' , 'env=ARG', 'the Edge organization (Default: test)'],
      ['k' , 'keyId=ARG', 'the keyId to use in the signature. Often this is the apikey.'],
      ['t' , 'path=ARG', 'the path to use (Default ' +  defaults.path + ')'],
      ['n' , 'nonce=ARG', 'set the nonce to use (Default: no nonce)'],
      ['H' , 'header=ARG+', 'set+sign an additional header (Name:value) in the request'],
      ['a' , 'algorithm=ARG', 'set the RSA alg to use (Default: '+defaults.alg+')'],
      ['X' , 'exclude-default-headers', 'exclude (request-target) date and user-agent from the headers to sign.'],
      ['N' , 'dontsend', 'do not send a request outbound.'],
      //['v', 'verbose'],
      ['h' , 'help']
 ]).bindHelp();

    // process.argv starts with 'node' and 'scriptname.js'
var opt = getopt.parse(process.argv.slice(2));

var MockRequest = function(opts) {
      var instance = {...opts};
      var xformedHeaders = {};
      Object.keys(instance.headers).forEach(key => {
        xformedHeaders[key.toLowerCase()] = instance.headers[key];
      });
      instance._headers = xformedHeaders;
      delete instance.headers;
      // public members
      instance.getHeader = function(name) {
        return instance._headers[name];
      };

      instance.setHeader = function(name, value) {
        instance._headers[name] = value;
      };

      instance.setHeader('date', (new Date()).toISOString());
      //instance.setHeader('user-agent', 'mock-request');

      return instance;
    };


function stringStartsWith(s, prefix, position) {
  position = position || 0;
  return s.lastIndexOf(prefix, position) === position;
}


function responseHandler(res) {
  console.log('==> ' + res.statusCode);
  var body = '';
  res.on('data', function(chunk) {
    body += chunk;
  });
  res.on('end', function() {
    console.log('body: ' + body);
  });
}


var requestOptions = {
  host: 'ORG-ENV.apigee.net',
  port: 80,
  path: '/httpsig/PATH?how=areyou',
  method: 'GET',
  headers: {
    'User-Agent' : 'nodejs httpSigClient.js'
  }
};

var signatureOptions = {
  key: null,
  algorithm: 'will-be-set-later',
  headers: opt.options['exclude-default-headers']?[]:[ '(request-target)', 'date', 'user-agent' ],
  draft: '04'
};



if ( ! opt.options.dontsend) {
  if (!opt.options.env) { opt.options.env = 'test'; }
  if (!opt.options.org) {
    console.log('missing org.');
    getopt.showHelp();
    process.exit(1);
  }
  requestOptions.host = opt.options.org + '-' + opt.options.env + '.apigee.net';
}

if (!opt.options.keyId) {
  console.log('missing apikey.');
  getopt.showHelp();
  process.exit(1);
}
signatureOptions.keyId = opt.options.keyId;


if ( ! opt.options.algorithm) {
  opt.options.algorithm = defaults.alg;
}
  opt.options.algorithm = opt.options.algorithm.toLowerCase();
  // validate the algorithm
  var supportedAlgorithms = ['rsa-sha1', 'rsa-sha256', 'rsa-sha512',
                             'hmac-sha1', 'hmac-sha256', 'hmac-sha512' ];
  if (supportedAlgorithms.indexOf(opt.options.algorithm) <0) {
    console.log('supported algorithms: ' + supportedAlgorithms.join(', '));
    getopt.showHelp();
    process.exit(1);
  }
  signatureOptions.algorithm = opt.options.algorithm;


// validate secretkey is used with HMAC and private key is used with RSA
if (stringStartsWith(opt.options.algorithm,'rsa')) {
  // rsa
  if (!opt.options.privkey) {
    console.log('missing private key.');
    getopt.showHelp();
    process.exit(1);
  }
  if (opt.options.secretkey) {
    console.log('secret key must not be specified with an RSA algorithm.');
    getopt.showHelp();
    process.exit(1);
  }

  if ( ! fs.existsSync(opt.options.privkey)) {
    console.log('That private keyfile does not exist.');
    getopt.showHelp();
    process.exit(1);
  }
  signatureOptions.key = fs.readFileSync(opt.options.privkey, 'ascii');
}
else {
  // hmac
  if (!opt.options.secretkey) {
    console.log('missing secret key.');
    getopt.showHelp();
    process.exit(1);
  }
  if (opt.options.privkey) {
    console.log('private key must not be specified with an HMAC algorithm.');
    getopt.showHelp();
    process.exit(1);
  }

  signatureOptions.key = opt.options.secretkey;
}


if (opt.options.path) {
  requestOptions.path = requestOptions.path.replace("PATH", opt.options.path);
}
else {
  requestOptions.path = requestOptions.path.replace("PATH", defaults.path);
}

// eliminate double-slashes
requestOptions.path =   requestOptions.path.replace("//", "/");

if (opt.options.nonce) {
  requestOptions.headers.nonce = opt.options.nonce;
  signatureOptions.headers.push('nonce');
}

// additional headers
if (opt.options.header) {
  let re1 = new RegExp(':(.+)');
  opt.options.header.forEach( (h) => {
    var parts = h.split(re1).map(Function.prototype.call, String.prototype.trim);
    requestOptions.headers[parts[0].toLowerCase()] = parts[1];
    signatureOptions.headers.push(parts[0].toLowerCase());
  });
}
//console.log(JSON.stringify(requestOptions, null, 2));

console.log('connecting to...');
console.log('  %s%s', requestOptions.host, requestOptions.path);
var req =
  (opt.options.dontsend)? MockRequest(requestOptions) : http.request(requestOptions, responseHandler);

// Adds a 'Date' header, computes the signature for the request using
// the provided private key, and finally adds the 'Authorization' header
// containing the signature.
httpSignature.sign(req, signatureOptions);

Object.keys(req._headers).forEach(function(key){
  console.log('HDR: %s: %s', key, req._headers[key]);
});

//?req.end();
