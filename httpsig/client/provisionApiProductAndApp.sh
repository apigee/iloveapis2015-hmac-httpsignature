#!/bin/bash
# -*- mode:shell-script; coding:utf-8; -*-
#
# provisionApiProductAndApp.sh
#
# A bash script for provisioning an API Product and a developer app on
# an organization in the Apigee Edge Gateway.
#
# Last saved: <2015-October-12 17:17:34>
#

verbosity=2
waittime=2
resetonly=0
deployalso=0
apiname=httpsig
quotalimit=500
envname=test
defaultmgmtserver="https://api.enterprise.apigee.com"
credentials=""
TAB=$'\t'

function usage() {
  local CMD=`basename $0`
  echo "$CMD: "
  echo "  Creates an API Product for the httpsig proxy, and a developer app"
  echo "  that is enabled for that product. Emits the client id and secret."
  echo "  Uses the curl utility."
  echo "usage: "
  echo "  $CMD [options] "
  echo "options: "
  echo "  -m url    the base url for the mgmt server."
  echo "  -o org    the org to use."
  echo "  -e env    the environment to deploy to."
  echo "  -u creds  http basic authn credentials for the API calls."
  echo "  -n        tells curl to use .netrc to retrieve credentials"
  echo "  -d        also deploy the bundle"
  echo "  -r        reset only; removes all ${apiname}-related configuration"
  echo "  -q        quiet; decrease verbosity by 1"
  echo "  -v        verbose; increase verbosity by 1"
  echo
  echo "Current parameter values:"
  echo "  mgmt api url: $defaultmgmtserver"
  echo "     verbosity: $verbosity"
  echo "   environment: $envname"
  echo
  exit 1
}

## function MYCURL
## Print the curl command, omitting sensitive parameters, then run it.
## There are side effects:
## 1. puts curl output into file named ${CURL_OUT}. If the CURL_OUT
##    env var is not set prior to calling this function, it is created
##    and the name of a tmp file in /tmp is placed there.
## 2. puts curl http_status into variable CURL_RC
function MYCURL() {
  local outargs
  local allargs
  local ix
  local ix2
  local re
  #re="^(-[du]|--user)$" # the curl options to not echo
  re="^(nope)$" # the curl options to not echo
  # grab the curl args, but skip the basic auth and the payload, if any.
  while [ "$1" ]; do
      allargs[$ix2]=$1
      let "ix2+=1"
      if [[ $1 =~ $re ]]; then
        shift
        allargs[$ix2]=$1
        let "ix2+=1"
      else
        outargs[$ix]=$1
        let "ix+=1"
      fi
      shift
  done

  [ -z "${CURL_OUT}" ] && CURL_OUT=`mktemp /tmp/apigee-${apiname}.curl.out.XXXXXX`

  [ -f "${CURL_OUT}" ] && rm ${CURL_OUT}

  if [ $verbosity -gt 1 ]; then
    # emit the curl command, without the auth + payload
    echo
    echo "curl ${outargs[@]}"
  fi
  # run the curl command
  CURL_RC=`curl $credentials -s -w "%{http_code}" -o "${CURL_OUT}" "${allargs[@]}"`
  if [ $verbosity -gt 1 ]; then
    # emit the http status code
    echo "==> ${CURL_RC}"
    echo
  fi
}


function echoerror() { echo "$@" 1>&2; }

function CleanUp() {
  if [ -f ${CURL_OUT} ]; then
    rm -rf ${CURL_OUT}
  fi
}


function choose_mgmtserver() {
  local name
  echo
  read -p "  Which mgmt server (${defaultmgmtserver}) :: " name
  name="${name:-$defaultmgmtserver}"
  mgmtserver=$name
  echo "  mgmt server = ${mgmtserver}"
}


function choose_credentials() {
  local creds

  echo
  echo -n "  Admin creds for ${mgmtserver}? (user:password) :: " 
  read -s creds

  echo
  credentials="-u $creds"
}


function check_org() {
  echo "  checking org ${orgname}..."
  MYCURL -X GET  ${mgmtserver}/v1/o/${orgname}
  if [ ${CURL_RC} -eq 200 ]; then
    check_org=0
  else
    check_org=1
  fi
}

function check_env() {
  echo "  checking environment ${envname}..."
  MYCURL -X GET  ${mgmtserver}/v1/o/${orgname}/e/${envname}
  if [ ${CURL_RC} -eq 200 ]; then
    check_env=0
  else
    check_env=1
  fi
}

function choose_org() {
  local all_done
  all_done=0
  while [ $all_done -ne 1 ]; do
      echo
      read -p "  Which org? " orgname
      check_org 
      if [ ${check_org} -ne 0 ]; then
        echo cannot read that org with the given creds.
        echo
        all_done=0
      else
        all_done=1
      fi
  done
  echo
  echo "  org = ${orgname}"
}


function choose_env() {
  local all_done
  all_done=0
  while [ $all_done -ne 1 ]; do
      echo
      read -p "  Which env? " envname
      check_env
      if [ ${check_env} -ne 0 ]; then
        echo cannot read that env with the given creds.
        echo
        all_done=0
      else
        all_done=1
      fi
  done
  echo
  echo "  env = ${envname}"
}


function random_string() {
  local rand_string
  rand_string=$(cat /dev/urandom |  LC_CTYPE=C  tr -cd '[:alnum:]' | head -c 10)
  echo ${rand_string}
}


## function clear_env_state
## Removes any developer app with the prefix of ${apiname}, and any
## developer or api product with that prefix, and any API with that
## name.
function clear_env_state() {
  local prodarray
  local devarray
  local apparray
  local revisionarray
  local prod
  local rev
  local dev
  local app
  local i
  local j

  echo "  check for developers like ${apiname}..."
  MYCURL -X GET ${mgmtserver}/v1/o/${orgname}/developers
  if [ ${CURL_RC} -ne 200 ]; then
    echo 
    echoerror "Cannot retrieve developers from that org..."
    exit 1
  fi
  devarray=(`cat ${CURL_OUT} | grep "\[" | sed -E 's/[]",[]//g'`)
  for i in "${!devarray[@]}"
  do
    dev=${devarray[i]}
    if [[ "$dev" =~ ^${apiname}.+$ ]] ; then
      echo "  found a matching developer..."
      echo "  list the apps for that developer..."
      MYCURL -X GET "${mgmtserver}/v1/o/${orgname}/developers/${dev}/apps"
      apparray=(`cat ${CURL_OUT} | grep "\[" | sed -E 's/[]",[]//g'`)
      for j in "${!apparray[@]}"
      do
        app=${apparray[j]}
        echo "  delete the app ${app}..."
        MYCURL  -X DELETE "${mgmtserver}/v1/o/${orgname}/developers/${dev}/apps/${app}"
        ## ignore errors
      done       

      echo "  delete the developer $dev..."
      MYCURL  -X DELETE "${mgmtserver}/v1/o/${orgname}/developers/${dev}"
      if [ ${CURL_RC} -ne 200 ]; then
        echo 
        echoerror "  could not delete that developer (${dev})"
        echo 
        exit 1
      fi
    fi
  done


  echo "  check for api products like ${apiname}..."
  MYCURL  -X GET ${mgmtserver}/v1/o/${orgname}/apiproducts
  if [ ${CURL_RC} -ne 200 ]; then
    echo 
    echoerror "Cannot retrieve apiproducts from that org..."
    exit 1
  fi

  prodarray=(`cat ${CURL_OUT} | grep "\[" | sed -E 's/[]",[]//g'`)
  for i in "${!prodarray[@]}"
  do
    prod=${prodarray[i]}

    if [[ "$prod" =~ ^${apiname}.+$ ]] ; then
       echo "  found a matching product...deleting it."
       MYCURL  -X DELETE ${mgmtserver}/v1/o/${orgname}/apiproducts/${prod}
       if [ ${CURL_RC} -ne 200 ]; then
         echo 
         echoerror "  could not delete that product (${prod})"
         echo 
         exit 1
       fi
    fi
  done

  echo "  check for the ${apiname} apiproxy..."
  MYCURL  -X GET ${mgmtserver}/v1/o/${orgname}/apis/${apiname}
  if [ ${CURL_RC} -eq 200 ]; then
    echo "  found, querying it..."

    MYCURL  -X GET ${mgmtserver}/v1/o/${orgname}/apis/${apiname}/revisions
    revisionarray=(`cat ${CURL_OUT} | grep "\[" | sed -E 's/[]",[]//g'`)
    for i in "${!revisionarray[@]}"
    do
      rev=${revisionarray[i]}
      echo "  undeploy the old apiproxy"
      MYCURL  -X POST "${mgmtserver}/v1/o/${orgname}/apis/${apiname}/revisions/${rev}/deployments?action=undeploy&env=${envname}"
      ## ignore errors
      echo "  delete the api revision"
      MYCURL  -X DELETE "${mgmtserver}/v1/o/${orgname}/apis/${apiname}/revisions/${rev}"
    done

    if [ $resetonly -eq 1 ] ; then

        echo "  delete the api"
        MYCURL  -X DELETE ${mgmtserver}/v1/o/${orgname}/apis/${apiname}
        if [ ${CURL_RC} -ne 200 ]; then
          echo "failed to delete that API"
        fi 
    fi 

  fi

}


function verify_public_key() {
  local pubkeyfile
  pubkeyfile=keys/key2-public.pem
  if [ ! -f $pubkeyfile ]; then
    echo "cannot find required public key at $pubkeyfile ..."
    echo "cannot continue."
    echo
    exit 1
  fi

  pubkey=$(<"$pubkeyfile")
  pubkey=`echo $pubkey | tr '\r\n' ' '`
}


function deploy_new_bundle() {
  if [ ! -d "../apiproxy/apiproxy" ] ; then 
     echo cannot find the apiproxy directory.
     echo re-run this command from the client directory. 
     echo
     exit 1
  fi

  if [ -f "$apiname.zip" ]; then
    if [ $verbosity -gt 0 ]; then
      echo "removing the existing zip..."
    fi
    rm -f "$apiname.zip"
  fi

  echo "  produce the bundle..."
  cd ../apiproxy
  zip -r "../client/${apiname}.zip" apiproxy  -x "*/*.*~" -x "*/Icon*" -x "*/#*.*#" -x "*/node_modules/*"
  cd ../client
  echo

  sleep 2
  echo "  import the bundle..."
  sleep 2
  MYCURL  -X POST \
       "${mgmtserver}/v1/o/${orgname}/apis/?action=import&name=${apiname}" \
       -T ${apiname}.zip -H "Content-Type: application/octet-stream"
  if [ ${CURL_RC} -ne 201 ]; then
    echo
    echoerror "  failed importing that bundle."
    cat ${CURL_OUT}
    echo
    echo
    exit 1
  fi

  echo "  deploy the ${apiname} apiproxy..."
  sleep 2
  MYCURL -X POST \
  "${mgmtserver}/v1/o/${orgname}/apis/${apiname}/revisions/1/deployments?action=deploy&env=$envname"
  if [ ${CURL_RC} -ne 200 ]; then
    echo
    echoerror "  failed deploying that api."
    cat ${CURL_OUT}
    echo
    echo
    exit 1
  fi
}



function create_new_product() {
  productname=${apiname}-`random_string`
  echo "  create a new product (${productname}) which contains that API proxy"
  sleep 2
  MYCURL \
    -H "Content-Type:application/json" \
    -X POST ${mgmtserver}/v1/o/${orgname}/apiproducts -d '{
   "approvalType" : "auto",
   "attributes" : [ ],
   "displayName" : "'${apiname}' Test product '${productname}'",
   "name" : "'${productname}'",
   "apiResources" : [ "/**" ],
   "description" : "Test for '${apiname}'",
   "environments": [ "'${envname}'" ],
   "proxies": [ "'${apiname}'" ],
   "quota": "'${quotalimit}'",
   "quotaInterval": "1",
   "quotaTimeUnit": "minute"
  }'
  if [ ${CURL_RC} -ne 201 ]; then
    echo
    echoerror "  failed creating that product."
    cat ${CURL_OUT}
    echo
    echo
    exit 1
  fi

  MYCURL -X GET ${mgmtserver}/v1/o/${orgname}/apiproducts/${productname}

  if [ ${CURL_RC} -ne 200 ]; then
    echo
    echoerror "  failed querying that product."
    cat ${CURL_OUT}
    echo
    echo
    exit 1
  fi

  cat ${CURL_OUT}
  echo
  echo
}



function create_new_developer() {
  local shortdevname=${apiname}-`random_string`
  devname=${shortdevname}@apigee.com
  echo  "  create a new developer (${devname})..."
  sleep 2
  MYCURL -X POST \
    -H "Content-type:application/json" \
    ${mgmtserver}/v1/o/${orgname}/developers \
    -d '{
    "email" : "'${devname}'",
    "firstName" : "Dino",
    "lastName" : "Valentino",
    "userName" : "'${shortdevname}'",
    "organizationName" : "'${orgname}'",
    "status" : "active"
  }' 
  if [ ${CURL_RC} -ne 201 ]; then
    echo
    echoerror "  failed creating a new developer."
    cat ${CURL_OUT}
    echo
    echo
    exit 1
  fi
}


function create_new_app() {
  local payload
  appname=${apiname}-`random_string`
  echo  "  create a new app (${appname}) for that developer, with authorization for the product..."
  sleep 2

payload=$'{\n'
payload+=$'  "attributes" : [ {\n'
payload+=$'     "name" : "creator",\n'
payload+=$'     "value" : "provisioning script '
payload+="$0"
payload+=$'"\n'
payload+=$'    },{\n'
payload+=$'     "name" : "public_key",\n'
payload+=$'     "value" : "'
payload+="$pubkey"
payload+=$'"\n'
payload+=$'    } ],\n'
payload+=$'  "apiProducts": [ "'
payload+="${productname}"
payload+=$'" ],\n'
payload+=$'    "callbackUrl" : "thisisnotused://www.apigee.com",\n'
payload+=$'    "name" : "'
payload+="${appname}"
payload+=$'",\n'
payload+=$'    "keyExpiresIn" : "100000000"\n'
payload+=$'}' 

#  pubkey=${pubkey// /\\ }
  # MYCURL -X POST \
  #   -H "Content-type:application/json" \
  #   ${mgmtserver}/v1/o/${orgname}/developers/${devname}/apps \
  #   -d '{
  #   "attributes" : [ {
  #         "name" : "creator",
  #         "value" : "provisioning script '$0'"
  #   },{
  #         "name" : "public_key",
  #         "value" : "'$pubkey'"
  #   } ],
  #   "apiProducts": [ "'${productname}'" ],
  #   "callbackUrl" : "thisisnotused://www.apigee.com",
  #   "name" : "'${appname}'",
  #   "keyExpiresIn" : "100000000"
  # }' 

  MYCURL -X POST \
    -H "Content-type:application/json" \
    ${mgmtserver}/v1/o/${orgname}/developers/${devname}/apps \
    -d "${payload}"

  if [ ${CURL_RC} -ne 201 ]; then
    echo
    echoerror "  failed creating a new app."
    cat ${CURL_OUT}
    echo
    echo
    exit 1
  fi
}

function retrieve_app_keys() {
  local array
  echo "  get the keys for that app..."
  sleep 2
  MYCURL -X GET \
    ${mgmtserver}/v1/o/${orgname}/developers/${devname}/apps/${appname} 

  if [ ${CURL_RC} -ne 200 ]; then
    echo
    echoerror "  failed retrieving the app details."
    cat ${CURL_OUT}
    echo
    echo
    exit 1
  fi  

  array=(`cat ${CURL_OUT} | grep "consumerKey" | sed -E 's/[",:]//g'`)
  consumerkey=${array[1]}
  array=(`cat ${CURL_OUT} | grep "consumerSecret" | sed -E 's/[",:]//g'`)
  consumersecret=${array[1]}

  echo "  consumer key: ${consumerkey}"
  echo "  consumer secret: ${consumersecret}"
  echo 
  sleep 2
}






## =======================================================

echo
echo "This script optionally deploys the ${apiname}.zip bundle, creates an API"
echo "product, inserts the API proxy into the product, creates a developer and"
echo "a developer app, gets the keys for that app. "
echo "=============================================================================="

while getopts "hm:o:e:u:ndrqv" opt; do
  case $opt in
    h) usage ;;
    m) mgmtserver=$OPTARG ;;
    o) orgname=$OPTARG ;;
    e) envname=$OPTARG ;;
    u) credentials="-u $OPTARG" ;;
    n) credentials="-n" ;;
    d) deployalso=1 ;;
    r) resetonly=1 ;;
    q) verbosity=$(($verbosity-1)) ;;
    v) verbosity=$(($verbosity+1)) ;;
    *) echo "unknown arg" && usage ;;
  esac
done

echo
if [ "X$mgmtserver" = "X" ]; then
  mgmtserver="$defaultmgmtserver"
fi 

echo
if [ "X$credentials" = "X" ]; then
  choose_credentials
fi 

echo
if [ "X$orgname" = "X" ]; then
  choose_org
else
  check_org 
  if [ ${check_org} -ne 0 ]; then
    echoerror "that org cannot be validated"
    CleanUp
    exit 1
  fi
fi 

## reset everything related to this api
clear_env_state

if [ $resetonly -eq 0 ] ; then

  verify_public_key
  if [ $deployalso -ne 0 ] ; then
    deploy_new_bundle
  fi
  create_new_product

  create_new_developer
  create_new_app
  retrieve_app_keys

fi

CleanUp
exit 0

