#!/bin/bash
# -*- coding: utf-8, tab-width: 2 -*-
SELFFILE="$(readlink -m "$0")"; SELFPATH="$(dirname "$SELFFILE")"
SELFNAME="$(basename "$SELFFILE" .sh)"


function main () {
  cd "$SELFPATH" || return $?
  local APPNAME='drop-a-note'

  if [ -n "$SOCAT_PEERADDR" ]; then
    https_serve_req
    return $?
  fi

  case "$1" in
    --test-defused2tty )
      perl -e '
        binmode STDOUT;
        for $idx (0..255, 10) { print chr($idx); }
        ' | defused2tty
      return $?;;
    --defused2tty ) defused2tty; return $?;;
    -* ) return 1$(echo "E: unsupported option: $1" >&2);;
  esac

  local HTTPS_PORT="$1"; shift
  local CERT_PEM="$1"; shift
  local CERT_KEY="$1"; shift
  local SOCAT_OPTS=

  local CONFIG_CANDIDATES=(
    # first existing file wins
    "$HOME/.config/$APPNAME/$HOSTNAME".{cfg,rc,cfg.sh}
    "$HOME/.config/$APPNAME/cfg.sh"
    "$HOME/.config/$APPNAME".{cfg,rc,cfg.sh}
    "$HOME/.config/ssh/$APPNAME".{cfg,rc,cfg.sh}
    "$HOME/.$APPNAME.rc"
    )
  local CFG_FN=
  for CFG_FN in "${CONFIG_CANDIDATES[@]}"; do
    if [ -f "$CFG_FN" ]; then
      source "$CFG_FN" || return $?
      break
    fi
  done

  [ -n "$HTTPS_PORT" ] || HTTPS_PORT=8074
  [ -n "$CERT_PEM" ] || CERT_PEM="$HOSTNAME".pem
  [ -r "$CERT_PEM" ] || return 5$(echo "E: cannot read SSL cert: $CERT_PEM" >&2)
  [ -n "$CERT_KEY" ] || CERT_KEY="$CERT_PEM"
  [ -r "$CERT_KEY" ] || return 5$(echo "E: cannot read SSL key: $CERT_KEY" >&2)

  local DROPANOTE_LOGFN="$HOME/.cache/$APPNAME"
  mkdir -p "$DROPANOTE_LOGFN"
  DROPANOTE_LOGFN+="/$HTTPS_PORT.$(date +'%Y-%m%d-%H%M').$$.log"
  export DROPANOTE_LOGFN
  echo -n "Trying to append to logfile $DROPANOTE_LOGFN: "
  >>"$DROPANOTE_LOGFN" || return $?
  echo 'ok.'

  local SOCAT_HTTPS="OPENSSL-LISTEN:$HTTPS_PORT"
  SOCAT_OPTS="${SOCAT_OPTS%,}"
  SOCAT_OPTS="${SOCAT_OPTS#,}"
  [ -n "$SOCAT_OPTS" ] && SOCAT_HTTPS+=",$SOCAT_OPTS"
  SOCAT_HTTPS+=",reuseaddr,fork"
  SOCAT_HTTPS+=",method=TLSv1,verify=0"
  SOCAT_HTTPS+=",cert=$CERT_PEM"
  SOCAT_HTTPS+=",key=$CERT_KEY"
  exec 2>&1
  srvlog "Serving on https://$HOSTNAME:$HTTPS_PORT/ ..."
  socat "$SOCAT_HTTPS" EXEC:"$SELFFILE"

  return 0
}


function srvlog () {
  <<<"$(date +'%F %T') #$$ $*" tee -a "$DROPANOTE_LOGFN" | defused2tty
}


function gen_sed_utf8ctrl () {
  local -A UTF8_HEX
  UTF8_HEX[replm-char]='\xef\xbf\xbd'
  UTF8_HEX[ctrl-cr]='\xe2\x90\x8d'
  UTF8_HEX[ctrl-lf]='\xe2\x90\x8a'
  UTF8_HEX[ctrl-nl]='\xe2\x90\xa4'
  UTF8_HEX[ctrl-tab]='\xe2\x90\x89'
  UTF8_HEX[ctrl-esc]='\xe2\x90\x9b'
  UTF8_HEX[ctrl-del]='\xe2\x90\xa1'
  echo '
    s~\x01~\n~g   # unpack newlines
    s~\x1b~'"${UTF8_HEX[ctrl-esc]}"'~g
    s~\x00~'"${UTF8_HEX[replm-char]}"'~g
    # s~\n~'"${UTF8_HEX[ctrl-lf]}"'&~g
    # UTF-8 control char symbols:
    s~\r~'"${UTF8_HEX[ctrl-cr]}"'~g
    s~\t~'"${UTF8_HEX[ctrl-tab]}"'~g
    s~\x7f~'"${UTF8_HEX[ctrl-del]}"'~g
    '
}


function gen_sed_ansi_invert () {
  echo '
    s~\x01~\n~g   # unpack newlines
    s~\x1b~\x1b[7m^[\x1b[0m~g
    s~\x00~\x1b[7m?\x1b[0m~g
    s~\t~\x1b[7m>\x1b[0m~g
    s~[\r\n]+~&\t~g
    /\n.*\n/!s~(^|[^\r])\n\t$~\1\t~
    s~\r~\x1b[7m<\x1b[0m~g
    s~\n~\x1b[7m,\x1b[0m~g
    s~\t~\n~g
    s~\x7f~\x1b[7m^H\x1b[0m~g
    '
}

function defused2tty () {
  # local SED_SCRIPT="$(gen_sed_utf8ctrl)"
  local SED_SCRIPT="$(gen_sed_ansi_invert)"
  [ -n "$SED_SCRIPT" ] || SED_SCRIPT='b no_sed_script'
  tr -c '\n\r\t\033\040-\177' '\000' \
    | tr '\n' '\001' | csed -re "$SED_SCRIPT" >&2
}


function https_serve_req () {
  local WWW_ROOT=.
  local CTRL_CR="$(echo -ne '\r')"
  local REQ_PATH=
  read -r REQ_PATH || return 0  # 1$(echo "E: $$: no request" >&2)
  REQ_PATH="${REQ_PATH%$CTRL_CR}"
  local REMOTE_ADDR="$SOCAT_PEERADDR"
  srvlog "$REMOTE_ADDR $REQ_PATH"

  local REQ_MTHD="${REQ_PATH%% *}"
  REQ_MTHD="${REQ_MTHD,,}"
  case "$REQ_MTHD" in
    get | post ) REQ_PATH="${REQ_PATH#* }";;
    * ) https_error 400 'Bad Request' 'unsupported method';;
  esac

  local REQ_PROTO="${REQ_PATH##* }"
  case "$REQ_PROTO" in
    'HTTP/1.0' | 'HTTP/1.1' ) REQ_PATH="${REQ_PATH% *}";;
    * ) https_error 400 'Bad Request' 'unsupported protocol version';;
  esac

  local REQ_HEAD="$(timeout 2s cat | head -c 4k)"
  local REQ_BODY="$(<<<"$REQ_HEAD" grep -xPe '\r?' -A ${#REQ_HEAD} \
    | tail -n +2)"
  REQ_HEAD="$(<<<"$REQ_HEAD" grep -xPe '\r?' -m 1 -B ${#REQ_HEAD})"

  case "$REQ_PATH" in
    /contact-form/* | \
    /"$APPNAME"/* )
      REQ_PATH="/${REQ_PATH#/*/}";;
  esac

  case "$REQ_PATH" in
    /submit.cgi )
      # serve_debug; return $?
      serve_submit
      return $?;;
    /socat-debug )
      serve_debug
      return $?;;
    / )
      echo -e 'HTTP/1.0 302 Found\r\nLocation: compose.html\r\n\r'
      return 0;;
  esac

  [ "$REQ_MTHD" == get ] || https_error 405 'Method not allowed'
  <<<"$REQ_PATH" grep -qxPe '(/[a-z0-9][a-z0-9_\-\.]{0,20}){1,5}' \
    || https_error 403 'Access denied' 'Suspicious URI'
  local CTYPE=application/octet-stream
  local FN_EXT="${REQ_PATH##*.}"
  case "$FN_EXT" in
    html ) CTYPE=text/"$FN_EXT";;
    txt ) CTYPE=text/plain;;
    js ) CTYPE=application/javascript;;
    ico ) CTYPE=image/x-icon;;
    jpg ) CTYPE=image/jpeg;;
    jpeg | gif | png ) CTYPE=image/"$FN_EXT";;
    * ) https_error 403 'Access denied';;
  esac

  REQ_PATH="${REQ_PATH#/}"
  [ -f "$WWW_ROOT/$REQ_PATH" ] || https_error 404 'Page not found'
  local CLENGTH="$(stat -c %s "$WWW_ROOT/$REQ_PATH")"
  https_reply_head
  cat "$WWW_ROOT/$REQ_PATH"
}


function https_reply_head () {
  local DOC_TITLE="$1"; shift
  [ -n "$HTTP_STATUS" ] || local HTTP_STATUS='200 Ok'
  srvlog "$HTTP_STATUS CT:${CTYPE:-auto}[${CLENGTH:-?}] DT:${DOC_TITLE:---}"
  echo -e "HTTP/1.0 $HTTP_STATUS\r"
  echo -e "Content-Type: ${CTYPE:-text/html}\r"
  [ -n "$CLENGTH" ] && echo -e "Content-Length: $CLENGTH\r"
  echo -e '\r'
  if [ -z "$CTYPE" ]; then
    echo '<!DOCTYPE html><html lang="en"><head>'
    echo '  <meta charset="UTF-8" />'
    echo "  <title>$DOC_TITLE</title>"
    echo '</head><body>'
  fi
}


function https_error () {
  local ERR_NUM="$1"; shift
  local ERR_TITLE="$1"; shift
  local HTTP_STATUS="$ERR_NUM $ERR_TITLE"
  local ERR_DESCR="$1"; shift
  https_reply_head "$ERR_TITLE"
  echo "  <h2>$ERR_TITLE</h2>"
  [ -n "$ERR_DESCR" ] && echo "  <p>$ERR_DESCR</p>"
  echo '</body></html>'
  exit 0
}


function serve_debug () {
  CTYPE=text/plain https_reply_head
  echo -ne 'DATE:\t'; date -R
  echo
  env | csed -nre 's~^SOCAT_([A-Z0-9]+)=~\1: \t~p' | sort
  echo
  echo 'head:'
  <<<"$REQ_HEAD" less | nl -ba
  echo 'body:'
  <<<"$REQ_BODY" less | nl -ba
}


function csed () {
  LANG=C sed "$@"
  return $?
}


function serve_submit () {
  <<<"$REQ_BODY" tee -a "$DROPANOTE_LOGFN" | defused2tty
  echo "D: request has been logged to $DROPANOTE_LOGFN" >&2
  https_reply_head
  echo "  <p>[$(date +%T)] received ${#REQ_BODY} bytes</p>"
  echo '</body></html>'
}












main "$@"; exit $?
