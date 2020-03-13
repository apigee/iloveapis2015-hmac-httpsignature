#!/bin/bash
# -*- mode:shell-script; coding:utf-8; -*-
#
# Created: <Wed Oct 21 16:58:12 2015>
# Last Updated: <2020-March-13 08:55:50>
#

payload="Four score and seven years ago our fathers brought forth on this continent, a new nation, conceived in Liberty, and dedicated to the proposition that all men are created equal."


function usage() {
  local CMD=`basename $0`
  echo "$CMD: "
  echo "  Invokes the hmac proxy."
  echo "  Uses the curl utility."
  echo "usage: "
  echo "  $CMD [options] "
  echo "options: "
  echo "  -o org      Edge organization"
  echo "  -e env      Edge environment"
  echo "  -k key      client_id"
  echo "  -s secret   client_secret (for computing HMAC)"
  echo "  -p payload  specify the payload to send"
  echo "  -m hmac     the hmac (base64) for that payload"
  echo
  echo
  exit 1
}

echo
echo "This script invokes the hmac API Proxy."
echo "=============================================================================="
sleep 2

while getopts "ho:e:k:s:p:m:" opt; do
  case $opt in
    h) usage ;;
    o) orgname=$OPTARG ;;
    e) envname=$OPTARG ;;
    k) key=$OPTARG ;;
    s) secret=$OPTARG ;;
    p) payload=$OPTARG ;;
    m) hmac_base64=$OPTARG ;;
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

if [ "X$secret" = "X" -a "X$hmac_base64" = "X" ]; then
  echo "Specify either an API secret with the -s option, or an hmac with the -h option"
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


if [ "X$hmac_base64" = "X" ]; then
  hmac_base64=`echo -n "$payload" | openssl dgst -sha256 -binary -hmac "${secret}" | openssl enc -base64`
fi

endpoint=https://${orgname}-${envname}.apigee.net/hmac/with-apikey


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
