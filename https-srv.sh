#!/bin/bash
# -*- coding: utf-8, tab-width: 2 -*-


function drop_a_note () {
  local APPNAME="${FUNCNAME//_/-}"
  export LANG{,UAGE}=en_US.UTF-8  # make error messages search engine-friendly
  local SELFFILE="$(readlink -m -- "$BASH_SOURCE")"
  local SELFPATH="$(dirname -- "$SELFFILE")"
  cd -- "$SELFPATH" || return $?

  local -A CFG=(
    [explicit_ssl_method]=  # Deprecated; use only for ancient socat.
    [handler_installers]='cfg_default_dropanote_handlers'
    [socat-opts]=
    )
  [ -n "$DROPANOTE_CONFIG" ] || local DROPANOTE_CONFIG="$(guess_config_file)"
  [ "${DEBUGLEVEL:-0}" -lt 2 ] || echo D: "config file: $CFG_FN" >&2
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

  drop_a_note_socat_switch "$@" || return $?
}


function drop_a_note_socat_switch () {
  if [ -n "$SOCAT_PEERADDR" ]; then
    https_serve_req
    return $?
  fi

  [ -z "$1" ] || CFG[https-port]="$1"; shift
  [ -z "$1" ] || CFG[cert-pem]="$1"; shift
  [ -z "$1" ] || CFG[cert-key]="$1"; shift
  [ -z "$DROPANOTE_CONFIG" ] \
    || in_func source -- "$DROPANOTE_CONFIG" || return $?

  cfg_default https-port 8074
  cfg_maybe_set_default_certs || return $?

  local DROPANOTE_LOGFN="${CFG[logsdir]:-$HOME/.cache/$APPNAME}"
  mkdir --parents -- "$DROPANOTE_LOGFN"
  DROPANOTE_LOGFN+="/${CFG[https-port]}.$(mostly_unique_id).log"
  export DROPANOTE_LOGFN
  echo -n "Trying to append to logfile $DROPANOTE_LOGFN: "
  >>"$DROPANOTE_LOGFN" || return $?
  echo 'ok.'

  local SSL_MTHD="${CFG[explicit_ssl_method]}"
  local LSN_PORT="${CFG[https-port]}"
  local SOCAT_LISTEN="OPENSSL-LISTEN:$LSN_PORT"
  local URL_PROTO='https'
  case "$SSL_MTHD" in
    unencrypted ) URL_PROTO='http'; SOCAT_LISTEN="TCP-LISTEN:$LSN_PORT";;
  esac
  local SOCK_OPTS="${CFG[socat-opts]}"
  SOCK_OPTS="${SOCK_OPTS%,}"
  SOCK_OPTS="${SOCK_OPTS#,}"
  [ -n "$SOCK_OPTS" ] && SOCAT_LISTEN+=",$SOCK_OPTS"
  SOCAT_LISTEN+=",reuseaddr,fork"

  if [ "$SSL_MTHD" != unencrypted ]; then
    SOCAT_LISTEN+=",verify=0"
    [ -z "$SSL_MTHD" ] || SOCAT_LISTEN+=",method=$SSL_MTHD"
    SOCAT_LISTEN+=",cert=${CFG[cert-pem]}"
    SOCAT_LISTEN+=",key=${CFG[cert-key]}"
  fi
  exec 2>&1
  srvlog "Serving on $URL_PROTO://$HOSTNAME:$LSN_PORT/ ..."
  socat "$SOCAT_LISTEN" EXEC:"$SELFFILE" || return $?
}


function in_func () { "$@"; }


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
  local -A UTF8_HEX=(
    [replm-char]='\xef\xbf\xbd'
    [ctrl-cr]='\xe2\x90\x8d'
    [ctrl-lf]='\xe2\x90\x8a'
    [ctrl-nl]='\xe2\x90\xa4'
    [ctrl-tab]='\xe2\x90\x89'
    [ctrl-esc]='\xe2\x90\x9b'
    [ctrl-del]='\xe2\x90\xa1'
    )
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


function https_temp_redir () {
  local DEST="$1"
  [ -n "$DEST" ] || https_error 500 'Internal Server Error' 'bad redirect'
  local EXTRA_HEADER="Location: $DEST"
  CTYPE='-/-' HTTP_STATUS=302 https_reply_head 'Found'
}


function https_temp_redir_file () {
  # pick the earliest file that exists, or the last option if none exist.
  local FN="$*"
  FN="${FN// /$'\n'}"
  FN="${FN//\|/$'\n'}"
  local FNS=()
  readarray -t FNS <<<"$FN"
  for FN in "${FNS[@]}"; do
    [ -f "${REQ_BASEDIR:-.}/$FN" ] && break
  done
  [ -n "$FN" ] && FN="./$FN"
  "${FUNCNAME%_*}" "$FN"
  return $?
}


function https_require_basic_auth_for () {
  local EXTRA_HEADER='WWW-Authenticate: Basic realm="%"'
  EXTRA_HEADER="${EXTRA_HEADER//%/$*}"
  https_error 401 'Login required'
  return $?
}


function https_serve_req () {
  local REQ_PATH="$(https_read_header_lines 1)"
  [ -n "$REQ_PATH" ] || return 0  # 1$(echo "E: $$: no request" >&2)
  local REQ_HEAD="$(echo "$REQ_PATH"; https_read_header_lines 128)"
  local REMOTE_ADDR="$SOCAT_PEERADDR"
  local REQ_MTHD="${REQ_PATH%% *}"
  REQ_MTHD="${REQ_MTHD,,}"
  REQ_PATH="${REQ_PATH#* }"
  local REQ_PROTO="${REQ_PATH##* }"
  REQ_PATH="${REQ_PATH% *}"

  local REQ_CLEN="$(<<<"$REQ_HEAD" grep -xPe 'Content-Length:\s*\d+' -m 1 \
    | grep -oPe '\d+$')"
  local REQ_AUTH="$(<<<"$REQ_HEAD" sed -nre 's~^Authorization:\s*~~p')"
  local REQ_ALLCOOKIES="$(<<<"$REQ_HEAD" sed -nre '
    s~\r~~g
    s~\s*\;\s*~\n~g
    s~^Cookie:\s*~~p')"
  local -A REQ_COOKIES=() # not implemented yet
  local REQ_SESS="$(<<<"$REQ_ALLCOOKIES" grep -xPe 'sess=[A-Za-z0-9_\-]+' \
    -m 1 | cut -d = -f 2-)"

  local REQ_LOGMSG="$REMOTE_ADDR $REQ_MTHD $REQ_PATH"
  [ "${REQ_CLEN:-0}" -gt 0 ] && REQ_LOGMSG+=" body:$REQ_CLEN"
  [ -n "$REQ_SESS" ] && REQ_LOGMSG+=" sess:$REQ_SESS"
  srvlog "$REQ_LOGMSG"

  [ -z "$DROPANOTE_CONFIG" ] \
    || in_func source -- "$DROPANOTE_CONFIG" || return $?
  cfg_default accept-methods get,put,post
  cfg_default url-maxlen 314
  cfg_default body-maxlen 31415
  cfg_default www-root "$SELFPATH"
  cfg_default legit_path_rgx '/|(/[a-z0-9][a-z0-9_\.\-]{0,40}){1,8}/?'
  cfg_default index-fn index.html
  cfg_install_handlers || return $?

  case "$REQ_PROTO" in
    'HTTP/1.0' | 'HTTP/1.1' ) ;;
    * ) https_error 400 'Bad Request' 'unsupported protocol version';;
  esac

  [[ " ${CFG[accept-methods]//$',\t\r\n'/ } " == *" $REQ_MTHD "* ]] \
    || https_error 400 'Bad Request' 'unsupported method'

  [ "${#REQ_PATH}" -le "${CFG[url-maxlen]}" ] \
    || https_error 414 'URI too long' "max. ${CFG[url-maxlen]} bytes"
  [ "${REQ_CLEN:-0}" -le "${CFG[body-maxlen]}" ] \
    || https_error 413 'Payload too large' "max. ${CFG[body-maxlen]} bytes"

  local REQ_QSTR="${REQ_PATH#*\?}"
  [ "$REQ_QSTR" == "$REQ_PATH" ] && REQ_QSTR=
  export QUERY_STRING="$REQ_QSTR"
  REQ_PATH="${REQ_PATH%%\?*}"

  <<<"$REQ_PATH" grep -qxPe "${CFG[legit_path_rgx]}" \
    || https_error 403 'Access denied' 'Suspicious URL'
  REQ_PATH="${REQ_PATH#/}"
  local REQ_BASEDIR="$(dirname "$REQ_PATH"x)"

  local REQ_FILE="${CFG[path:$REQ_PATH]}"
  [ -n "$REQ_FILE" ] || REQ_FILE="www:$REQ_PATH"
  local HND_CMD=( "${REQ_FILE%%:*}" )
  [ "${HND_CMD[0]}" == "$REQ_FILE" ] && HND_CMD=( '??' )
  REQ_FILE="${REQ_FILE#*:}"
  case "${HND_CMD[0]}" in
    www )
      HND_CMD=( serve_file )
      REQ_FILE="${CFG[www-root]%/}/$REQ_FILE";;
    404 )
      HND_CMD=( https_error 404 'Page not found' )
      REQ_FILE=;;
    http-err ) HND_CMD=( https_error );;
    file ) HND_CMD=( serve_file );;
    reply )
      srvlog "replaying exact response file: $REQ_FILE"
      HND_CMD=( cat -- );;
    serve )
      HND_CMD=( "${HND_CMD[0]}_${REQ_FILE}" )
      REQ_FILE=;;
    eval ) ;;
    stdio )       HND_CMD=( serve_wrap_stdio );;
    stdio+eval )  HND_CMD=( serve_wrap_stdio eval );;
    redir )       HND_CMD=( https_temp_redir );;
    redir+file )  HND_CMD=( https_temp_redir_file );;
    * ) https_error 500 'Internal Server Error' 'config: bad alias';;
  esac

  [ "${DEBUGLEVEL:-0}" -ge 1 ] && \
    srvlog "response: ${HND_CMD[*]} '$REQ_FILE'"
  if [ -n "$REQ_FILE" ]; then
    [ "${REQ_FILE:0:2}" == '~/' ] && REQ_FILE="$HOME/${REQ_FILE:2}"
    HND_CMD+=( "$REQ_FILE" )
  fi
  "${HND_CMD[@]}"
  return 0
}


function cfg_maybe_set_default_certs () {
  case "${CFG[explicit_ssl_method]}" in
    unencrypted ) return 0;;
  esac

  cfg_default cert-pem "$HOSTNAME".pem
  [ -r "${CFG[cert-pem]}" ] || return 5$(
    echo "E: cannot read SSL cert: ${CFG[cert-pem]}" >&2)
  cfg_default cert-key "${CFG[cert-pem]}"
  [ -r "${CFG[cert-key]}" ] || return 5$(
    echo "E: cannot read SSL key: ${CFG[cert-key]}" >&2)
}


function cfg_install_handlers () {
  local HND=
  for HND in ${CFG[handler_installers]}; do
    "$HND" || return $?$(echo E: "Failed to $FUNCNAME '$HND'" >&2)
  done
}


function cfg_default_dropanote_handlers () {
  cfg_default path: 'redir+file:index.html compose.html'
  cfg_default path:submit.cgi serve:submit
  cfg_default path:socat_debug serve:socat_debug
  cfg_default path:dwnl/ serve:dwnl_redir
  cfg_default expiry:get+fext:ico '+12 hours'
  cfg_default expiry:get+fext:png '+12 hours'
  cfg_default expiry:get+fext:js '+1 hour'
  cfg_default expiry:get+fext:html '+1 hour'
}


function auch_basic_check_file () {
  local AUTH_FILE="$1"; shift
  local AUTH_METHOD="${REQ_AUTH%% *}"
  [ "${AUTH_METHOD,,}" == basic ] || return 11
  local AUTH_USER="${REQ_AUTH# *}"
  [ -n "$AUTH_USER" ] || return 12
  [ -f "$AUTH_FILE" ] || return 13
  grep -qxFe "$REQ_AUTH" "$AUTH_FILE" || return 14
  return 0
}


function serve_file () {
  local SRC_FN="$1"; shift
  [ "$REQ_MTHD" == get ] || https_error 405 'Method not allowed'
  case "$SRC_FN" in
    */ ) https_temp_redir_file "${CFG[index-fn]}"; return $?;;
  esac
  [ -f "$SRC_FN" ] || https_error 404 'Page not found'
  [ -r "$SRC_FN" ] || https_error 403 'Access denied'

  local AUTH_FILE=
  for AUTH_FILE in "$SRC_FN".{auth,passwd} ''; do
    [ -n "$AUTH_FILE" -a -e "$AUTH_FILE" ] && break
  done
  if [ -n "$AUTH_FILE" ]; then
    if ! auch_basic_check_file "$AUTH_FILE"; then
      srvlog "failed auth attempt: $REQ_AUTH"
      https_require_basic_auth_for "/$REQ_PATH"
      return $?
    fi
  fi

  local FN_EXT_ORIG="${REQ_PATH##*.}"
  local CTYPE="${CFG[ctype:$FN_EXT_ORIG]}"
  if [ -z "$CTYPE" ]; then
    case "$FN_EXT_ORIG" in
      html  ) CTYPE=text/"$FN_EXT_ORIG";;
      txt   ) CTYPE=text/plain;;
      js    ) CTYPE=application/javascript;;
      json  ) CTYPE=application/"$FN_EXT_ORIG";;

      ico   ) CTYPE=image/x-icon;;
      jpg   ) CTYPE=image/jpeg;;
      gif | jpeg | png ) CTYPE=image/"$FN_EXT_ORIG";;

      tar | gz | tgz | bz2 | \
      arj | cab | lzh | rar | \
      zip ) CTYPE=application/x-compressed;;

      dll | exe | iso | \
      bin ) CTYPE=application/octet-stream;;

      auth | passwd ) CTYPE=http/403;;
      * ) CTYPE=http/403;;
    esac
  fi
  [ "$CTYPE" == http/403 ] && https_error 403 'Access denied'
  [ -n "$CTYPE" ] || CTYPE=application/octet-stream

  local SRC_FLT="${CFG[filter:$FN_EXT_ORIG]}"
  if [ -n "$SRC_FLT" ]; then
    [ "${SRC_FLT:0:2}" == '~/' && SRC_FLT="$HOME/${SRC_FLT:2}"
    if [ "${SRC_FLT:0:1}" != / ]; then
      if [ "$(type -t "$SRC_FLT")" != function ]; then
        SRC_FLT="$(try_which "$SRC_FLT")"
        [ -x "$SRC_FLT" ] \
          || https_error 500 'Internal Server Error' 'cannot run filter'
      fi
    fi
    https_reply_head
    "$SRC_FLT" "$SRC_FN"
    return 0
  fi

  [ -n "$EXPIRY_DATE" ] || local EXPIRY_DATE=$(
    )"${CFG[expiry:get+fext:$FN_EXT_ORIG]}"
  CLENGTH="$(stat -c %s "$SRC_FN")" https_reply_head
  cat "$SRC_FN"
  return 0
}


function try_which () {
  which "$1" 2>/dev/null | grep -Pe '^/' -m 1 || echo "$1"
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
  local UTC_DATE="$(date -Ru "$@")"
  echo "${UTC_DATE% *} UTC"
}


function https_reply_head () {
  local DOC_TITLE="$1"; shift
  [ -n "$HTTP_STATUS" ] || local HTTP_STATUS='200 Ok'
  srvlog "$HTTP_STATUS CT:${CTYPE:-auto}[${CLENGTH:-?}] DT:${DOC_TITLE:---}"
  printf '%s\r\n' "HTTP/1.0 $HTTP_STATUS" "Date: $(http_date)"

  local EXPY="$EXPIRY_DATE"
  [ -n "$EXPY" ] || EXPY="${CFG[expiry:$REQ_MTHD:$REQ_PATH]}"
  [ -n "$EXPY" ] || EXPY="${CFG[expiry:*:$REQ_PATH]}"
  [ -n "$EXPY" ] || EXPY="${CFG[expiry:$REQ_MTHD:*]}"
  [ -n "$EXPY" ] || EXPY="${CFG[expiry:*:*]}"
  [ -n "$EXPY" ] || EXPY='@42'
  [ "$EXPY" != - ] && printf '%s\r\n' "Expires: $(http_date --date="$EXPY")"

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
  HTTP_STATUS="$ERR_NUM $ERR_TITLE" CTYPE= https_reply_head "$ERR_TITLE"
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


function serve_dwnl_redir () {
  [ "$REQ_MTHD" == get ] || https_error 405 'Method not allowed'
  local DL_FN="/${REQ_QSTR#\.=}"
  DL_FN="$(<<<"$DL_FN" grep -xPe "${CFG[legit_path_rgx]}")"
  DL_FN="${DL_FN#/}"
  https_temp_redir_file "${DL_FN:-${CFG[index-fn]}}"
}


function serve_socat_debug () {
  CTYPE='text/plain' https_reply_head 'debug info'
  echo -ne 'DATE:\t'; date -R
  dump_socat_env 's~: ~&\t~'
  echo
  echo 'HEAD:'
  <<<"$REQ_HEAD" nl -ba
  echo 'BODY:'
  https_read_body | nl -ba
}


function serve_wrap_stdio () {
  CTYPE='text/plain' https_reply_head
  local STDIN_SRC=( https_read_body )
  [ "$REQ_MTHD" == get ] && STDIN_SRC=( false )
  "${STDIN_SRC[@]}" | "$@" 2>&1
}


function csed () {
  LANG=C sed "$@"
  return $?
}


function serve_submit () {
  https_reply_head

  local SAVE_BFN="${CFG[body-storage]}"
  local BODY_SIZE=
  local RV=
  [ "${DEBUGLEVEL:-0}" -ge 4 ] && dump_socat_env 's!^!X-Socat-!' >&2
  [ "${DEBUGLEVEL:-0}" -ge 2 ] && <<<"$REQ_HEAD" defused2tty

  if [ -n "$SAVE_BFN" ]; then
    SAVE_BFN+="$(mostly_unique_id)"
    ( echo "$REQ_HEAD"
      LANG=C LC_ALL=C date +'X-Received-At: %s %a %F %T %z (%Z)'
      echo "X-Remote-Addr: $REMOTE_ADDR"
    ) >"$SAVE_BFN.head"
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
  echo "  <p>[$(date +%T)] received ${BODY_SIZE:-?error?} bytes</p>"
  echo '</body></html>'
  <<<"$REQ_BODY" defused2tty
}












[ "$1" == --lib ] && return 0; drop_a_note "$@"; exit $?
