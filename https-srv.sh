#!/bin/bash
# -*- coding: utf-8, tab-width: 2 -*-
SELFFILE="$(readlink -m "$0")"; SELFPATH="$(dirname "$SELFFILE")"
SELFNAME="$(basename "$SELFFILE" .sh)"


function main () {
  cd "$SELFPATH" || return $?
  local APPNAME='drop-a-note'

  local -A CFG
  [ -n "$DROPANOTE_CONFIG" ] || local DROPANOTE_CONFIG="$(guess_config_file)"
  [ "${DEBUGLEVEL:-0}" -gt 2 ] && echo "D: config file: $CFG_FN" >&2
  export DROPANOTE_CONFIG

  case "$1" in
    --test-defused2tty )
      perl -e '
        binmode STDOUT;
        for $idx (0..255, 10) { print chr($idx); }
        ' | defused2tty
      return $?;;
    --defused2tty ) defused2tty; return $?;;
    --read-body-maxlen )
      read_body_maxlen "${@:2}"
      return 0;;
    -* ) return 1$(echo "E: unsupported option: $1" >&2);;
  esac

  if [ -n "$SOCAT_PEERADDR" ]; then
    https_serve_req
    return $?
  fi

  CFG[https-port]="$1"; shift
  CFG[cert-pem]="$1"; shift
  CFG[cert-key]="$1"; shift
  CFG[socat-opts]=
  source "$DROPANOTE_CONFIG" || return $?

  cfg_default https-port 8074
  cfg_default cert-pem "$HOSTNAME".pem
  [ -r "${CFG[cert-pem]}" ] || return 5$(
    echo "E: cannot read SSL cert: ${CFG[cert-pem]}" >&2)
  cfg_default cert-key "${CFG[cert-pem]}"
  [ -r "${CFG[cert-key]}" ] || return 5$(
    echo "E: cannot read SSL key: ${CFG[cert-key]}" >&2)

  local DROPANOTE_LOGFN="${CFG[logsdir]:-$HOME/.cache/$APPNAME}"
  mkdir -p "$DROPANOTE_LOGFN"
  DROPANOTE_LOGFN+="/${CFG[https-port]}.$(mostly_unique_id).log"
  export DROPANOTE_LOGFN
  echo -n "Trying to append to logfile $DROPANOTE_LOGFN: "
  >>"$DROPANOTE_LOGFN" || return $?
  echo 'ok.'

  local SOCAT_HTTPS="OPENSSL-LISTEN:${CFG[https-port]}"
  local SOCK_OPTS="${CFG[socat-opts]}"
  SOCK_OPTS="${SOCK_OPTS%,}"
  SOCK_OPTS="${SOCK_OPTS#,}"
  [ -n "$SOCK_OPTS" ] && SOCAT_HTTPS+=",$SOCK_OPTS"
  SOCAT_HTTPS+=",reuseaddr,fork"
  SOCAT_HTTPS+=",method=TLSv1,verify=0"
  SOCAT_HTTPS+=",cert=${CFG[cert-pem]}"
  SOCAT_HTTPS+=",key=${CFG[cert-key]}"
  exec 2>&1
  srvlog "Serving on https://$HOSTNAME:${CFG[https-port]}/ ..."
  socat "$SOCAT_HTTPS" EXEC:"$SELFFILE"

  return 0
}


function srvlog () {
  <<<"$(date +'%F %T') #$$ $*" tee -a "$DROPANOTE_LOGFN" | defused2tty
}


function cfg_default () {
  [ -n "${CFG[$1]}" ] || CFG["$1"]="$2"
}


function mostly_unique_id () {
  date +"%Y-%m%d-%H%M-$$"
}


function guess_config_file () {
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
      echo "$CFG_FN"
      break
    fi
  done
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
    s~\x00~\x1b[7m¿\x1b[0m~g
    s~\t~\x1b[7m>\x1b[0m~g
    s~[\r\n]+~&\t~g
    /\n.*\n/!s~(^|[^\r])\n\t$~\1\t~
    s~\r~\x1b[7m«\x1b[0m~g
    s~\n~\x1b[7m¶\x1b[0m~g
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


function https_read_header_lines () {
  local MAXLN="${1:-0}"
  local CTRL_CR="$(echo -ne '\r')"
  local TIMEOUT_SEC=5
  local HDRLN=
  while [ "$MAXLN" -gt 0 ]; do
    read -r -s -t "$TIMEOUT_SEC" HDRLN || return $?
    HDRLN="${HDRLN%$CTRL_CR}"
    <<<"$HDRLN" grep -Pe '\S' || return 0
    let MAXLN="$MAXLN-1"
  done
}


function https_serve_req () {
  local REQ_PATH="$(https_read_header_lines 1)"
  [ -n "$REQ_PATH" ] || return 0  # 1$(echo "E: $$: no request" >&2)
  local REQ_HEAD="$(echo "$REQ_PATH"; https_read_header_lines 128)"
  local REMOTE_ADDR="$SOCAT_PEERADDR"
  local REQ_MTHD="${REQ_PATH%% *}"
  REQ_MTHD="${REQ_MTHD,,}"
  local REQ_PROTO="${REQ_PATH##* }"
  srvlog "$REMOTE_ADDR $REQ_PATH"

  local REQ_CLEN="$(<<<"$REQ_HEAD" grep -xPe 'Content-Length:\s*\d+' -m 1 \
    | grep -oPe '\d+$')"

  source "$DROPANOTE_CONFIG" || return $?
  cfg_default body-maxlen 102400
  cfg_default www-root "$SELFPATH"

  case "$REQ_MTHD" in
    get | post ) REQ_PATH="${REQ_PATH#* }";;
    * ) https_error 400 'Bad Request' 'unsupported method';;
  esac

  case "$REQ_PROTO" in
    'HTTP/1.0' | 'HTTP/1.1' ) REQ_PATH="${REQ_PATH% *}";;
    * ) https_error 400 'Bad Request' 'unsupported protocol version';;
  esac

  [ "${REQ_CLEN:-0}" -le "${CFG[body-maxlen]}" ] \
    || https_error 413 'Payload too large' "max. ${CFG[body-maxlen]} bytes"

  case "$REQ_PATH" in
    /contact-form/* | \
    /"$APPNAME"/* )
      REQ_PATH="/${REQ_PATH#/*/}";;
  esac

  local REQ_QSTR="${REQ_PATH#*\?}"
  [ "$REQ_QSTR" == "$REQ_PATH" ] && REQ_QSTR=
  REQ_PATH="${REQ_PATH%%\?*}"

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

  local LEGIT_PATH_RGX='(/[a-z0-9][a-z0-9_\-\.]{0,20}){1,5}'
  <<<"$REQ_PATH" grep -qxPe "$LEGIT_PATH_RGX" \
    || https_error 403 'Access denied' 'Suspicious URI'
  REQ_PATH="${REQ_PATH#/}"

  local REQ_FILE="${CFG[path:$REQ_PATH]}"
  case "$REQ_FILE" in
    home:* ) REQ_FILE="$HOME/${REQ_FILE#*:}";;
    file:* ) REQ_FILE="${REQ_FILE#*:}";;
    reply:* )
      REQ_FILE="${REQ_FILE#*:}"
      srvlog "replaying exact response file: $REQ_FILE"
      cat "$REQ_FILE"
      return 0;;
    cgi-source:* )
      REQ_FILE="${REQ_FILE#*:}"
      srvlog "source-CGI: $REQ_FILE"
      source "$REQ_FILE"
      return 0;;
    redir:* )
      EXTRA_HEADER="Location: ${REQ_FILE#*:}" CTYPE='-/-' \
        HTTP_STATUS=302 https_reply_head 'Found'
      return 0;;
    '' )
      REQ_FILE="${CFG[www-root]%/}/$REQ_PATH";;
    * ) https_error 500 'Internal Server Error' 'config: bad alias';;
  esac

  [ "$REQ_MTHD" == get ] || https_error 405 'Method not allowed'
  serve_file "$REQ_FILE"
}


function serve_file () {
  local SRC_FN="$1"; shift
  [ -f "$SRC_FN" ] || https_error 404 'Page not found'
  [ -r "$SRC_FN" ] || https_error 403 'Access Denied'

  local FN_EXT="${REQ_PATH##*.}"
  local CTYPE=
  case "$FN_EXT" in
    html ) CTYPE=text/"$FN_EXT";;
    txt ) CTYPE=text/plain;;
    js ) CTYPE=application/javascript;;
    ico ) CTYPE=image/x-icon;;
    jpg ) CTYPE=image/jpeg;;
    jpeg | gif | png ) CTYPE=image/"$FN_EXT";;
    * ) https_error 403 'Access denied';;
  esac
  [ -n "$CTYPE" ] || CTYPE=application/octet-stream

  local SRC_FLT="${CFG[filter:$FN_EXT]}"
  if [ -n "$SRC_FLT" ]; then
    [ -x "$SRC_FLT" ] \
      || CTYPE= https_error 500 'Internal Server Error' 'cannot run filter'
    https_reply_head
    "$SRC_FLT" "$SRC_FN"
    return 0
  fi

  CLENGTH="$(stat -c %s "$SRC_FN")" https_reply_head
  cat "$SRC_FN"
  return 0
}


function readpid_kill_after () {
  local TMO_PID=
  read -r TMO_PID
  "$@"
  kill "$TMO_PID" 2>/dev/null
}


function https_read_body () {
  local BODY_TIMEOUT='3s'
  local BODY_LEN="${CFG[body-maxlen]}"
  if [ -n "$REQ_CLEN" ]; then
    [ "$REQ_CLEN" -le "${CFG[body-maxlen]}" ] && BODY_LEN="$REQ_CLEN"
    BODY_TIMEOUT='10s'
  fi
  TMO="$BODY_TIMEOUT" sh -c 'echo $$; exec timeout "$TMO" cat' \
    | readpid_kill_after head --bytes="$BODY_LEN"
  # Timeout-killing the cat can leave head hanging <defunct>,
  # but timeout-killing the head can prevent it from printing
  # its output.
}


function http_date () {
  local UTC_DATE="$(date -Ru)"
  echo "${UTC_DATE% *} UTC"
}


function https_reply_head () {
  local DOC_TITLE="$1"; shift
  [ -n "$HTTP_STATUS" ] || local HTTP_STATUS='200 Ok'
  srvlog "$HTTP_STATUS CT:${CTYPE:-auto}[${CLENGTH:-?}] DT:${DOC_TITLE:---}"
  printf '%s\r\n' "HTTP/1.0 $HTTP_STATUS" "Date: $(http_date)"
  # [ -n "$DOC_TITLE" ] && printf '%s\r\n' "Title: $DOC_TITLE"
  [ "$CTYPE" != -/- ] && printf '%s\r\n' "Content-Type: ${CTYPE:-text/html}"
  [ -n "$CLENGTH" ] && printf '%s\r\n' "Content-Length: $CLENGTH"
  [ -n "$EXTRA_HEADER" ] && printf '%s\r\n' "$EXTRA_HEADER"
  printf '%s\r\n' ''
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
  local ERR_DESCR="$1"; shift
  HTTP_STATUS="$ERR_NUM $ERR_TITLE" https_reply_head "$ERR_TITLE"
  echo "  <h2>$ERR_TITLE</h2>"
  [ -n "$ERR_DESCR" ] && echo "  <p>$ERR_DESCR</p>"
  echo '</body></html>'
  exit 0
}


function dump_socat_env () {
  env | csed -re '
    /^SOCAT_/!d
    s~^SOCAT_([A-Z0-9])([A-Z0-9]*)=~\1\L\2\E: ~
    s~^(\w+)(addr|port):~\1\u\2\E:~
    s~^p*id:~\U&\E~i
    '"$1" | sort -V
}


function serve_debug () {
  CTYPE='text/plain' https_reply_head 'debug info'
  echo -ne 'DATE:\t'; date -R
  dump_socat_env 's~: ~&\t~'
  echo
  echo 'HEAD:'
  <<<"$REQ_HEAD" nl -ba
  echo 'BODY:'
  https_read_body | nl -ba
}


function csed () {
  LANG=C sed "$@"
  return $?
}


function serve_submit () {
  local SAVE_BFN="${CFG[body-storage]}"
  local BODY_SIZE=
  REQ_HEAD+="$(echo; echo
    LANG=C LC_ALL=C date +'X-Received-At: %s %a %F %T %z (%Z)'
    [ "${DEBUGLEVEL:-0}" -ge 4 ] && dump_socat_env 's!^!X-Socat-!'
    )"
  local RV=
  ( echo "$REQ_HEAD"; echo ) | tee -a "$DROPANOTE_LOGFN"
  [ "${DEBUGLEVEL:-0}" -ge 2 ] && <<<"$REQ_HEAD" defused2tty

  if [ -n "$SAVE_BFN" ]; then
    SAVE_BFN+="$(mostly_unique_id)"
    echo "$REQ_HEAD" >"$SAVE_BFN.head"
    RV=$?
    [ "$RV" == 0 ] || srvlog "E: Failed ($RV) to save $SAVE_BFN.head"
    REQ_BODY="$(https_read_body | tee -a "$DROPANOTE_LOGFN" "$SAVE_BFN.body")"
    RV=$?
    if [ "$RV" != 0 ]; then
      srvlog "E: Failed ($RV) to save $SAVE_BFN.body"
      https_error 503 'Service Unavailable' 'unable to record message'
    fi
    srvlog "D: request has been saved to $SAVE_BFN.{head,body}"
    BODY_SIZE="$(stat -c %s "$SAVE_BFN.body")"
  else
    REQ_BODY="$(https_read_body | tee -a "$DROPANOTE_LOGFN")"
    srvlog "D: request has been logged to $DROPANOTE_LOGFN"
    BODY_SIZE="${#REQ_BODY}"
  fi
  https_reply_head
  echo "  <p>[$(date +%T)] received ${BODY_SIZE:-?error?} bytes</p>"
  echo '</body></html>'
}












main "$@"; exit $?
