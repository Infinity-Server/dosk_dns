#!/usr/bin/env sh

dosk_auth="${Dosk_Auth:-"auth"}"
dosk_token="${Dosk_Token:-"token"}"
dosk_server="${Dosk_Server:-"http://localhost"}"

dns_dosk_add() {
  fulldomain="${1}"
  txtvalue="${2}"
  action="set"

  _debug "Dosk DNS: '${fulldomain}' '${txtvalue}' '${action}'"

  export _H1="${dosk_auth}: ${dosk_token}"
  response="$(_get "${dosk_server}/set/${fulldomain}/${txtvalue}" "" "")"
}

dns_dosk_rm() {
  fulldomain="${1}"
  txtvalue="${2}"
  action="del"

  _debug "Dosk DNS: '${fulldomain}' '${txtvalue}' '${action}'"
  export _H1="${dosk_auth}: ${dosk_token}"
  response="$(_get "${dosk_server}/del/${fulldomain}/${txtvalue}" "" "")"
}
