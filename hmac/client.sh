#!/bin/bash
# -*- mode:shell-script; coding:utf-8; -*-
#
# Created: <Wed Oct 21 16:58:12 2015>
# Last Updated: <2015-October-21 17:11:14>
#

payload="Four score and seven years ago our fathers brought forth on this continent, a new nation, conceived in Liberty, and dedicated to the proposition that all men are created equal."


function usage() {
  local CMD=`basename $0`
  echo "$CMD: "
  echo "  Creates an API Product for the hmac proxy, and a developer app"
  echo "  that is enabled for that product. Emits the client id and secret."
  echo "  Uses the curl utility."
  echo "usage: "
  echo "  $CMD [options] "
  echo "options: "
  echo "  -o org      Edge organization"
  echo "  -e env      Edge environment"
  echo "  -k key      client_id"
  echo "  -s secret   client_secret (for computing HMAC)"
  echo "  -p payload  specify the payload to send"
  echo
  echo
  exit 1
}

echo
echo "This script invokes the hmac API Proxy."
echo "=============================================================================="
sleep 2

while getopts "ho:e:k:s:p:" opt; do
  case $opt in
    h) usage ;;
    o) orgname=$OPTARG ;;
    e) envname=$OPTARG ;;
    k) key=$OPTARG ;;
    s) secret=$OPTARG ;;
    p) payload=$OPTARG ;;
    *) echo "unknown arg" && usage ;;
  esac
done

echo
if [ "X$key" = "X" ]; then
  echo "Specify an API key with the -k option" 
  echo
  usage
  exit 1
fi 

if [ "X$secret" = "X" ]; then
  echo "Specify an API secret with the -s option" 
  echo
  usage
  exit 1
fi 
if [ "X$orgname" = "X" ]; then
  echo "Specify an organization with the -o option" 
  echo
  usage
  exit 1
fi 
if [ "X$envname" = "X" ]; then
  echo "Specify an environment with the -e option" 
  echo
  usage
  exit 1
fi 


echo -n "value" | openssl dgst -sha256 -binary -hmac password | openssl enc -base64 

hmac_base64=`echo -n "$payload" | openssl dgst -sha256 -binary -hmac "${secret}" | openssl enc -base64`

endpoint=http://${orgname}-${envname}.apigee.net/hmac/with-apikey


echo curl -i -X POST \\
echo   -d "${payload}" \\
echo  -H "apikey: $key" \\
echo  -H "hmac-base64: $hmac_base64" \\
echo  $endpoint

curl -i -X POST \
  -d "${payload}" \
  -H "apikey: $key" \
  -H "hmac-base64: $hmac_base64" \
  $endpoint


