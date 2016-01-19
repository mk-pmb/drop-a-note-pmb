#!/bin/bash
# -*- coding: utf-8, tab-width: 2 -*-


function extract_file_upload () {
  local LOG_FN="$1"; shift
  local BOUNDARY=
  local SAVE_BFN=
  case "$LOG_FN" in
    *.body )
      BOUNDARY="$(head -n 1 -- "$LOG_FN" | tr -d '\r')"
      SAVE_BFN="$(basename "$LOG_FN" .body)"
      ;;
    * )
      BOUNDARY="$1"; shift
      SAVE_BFN="$1"; shift
      ;;
  esac

  local CD_FILE_RGX='Content-Disposition:.*;\s*filename=\x22'

  if [ -z "$BOUNDARY" ]; then
    grep -Pane '^'"$CD_FILE_RGX" -B 1 -- "$LOG_FN" | sed -re '
      s~\r~~g
      /^[0-9]+-/{
        N
        s~\r~~g
        s~"$~~
        s~^[0-9]+-(\S+)\n([0-9]+):'"$CD_FILE_RGX"'~\2 \1 ~
      }'
    return 0
  fi

  [ -n "$SAVE_BFN" ] || SAVE_BFN="$(date +'%y%m%d-%H%M%S')-$$"

  local BOUND_LNUMS=( $(find_boundary_lnums "$LOG_FN" "$BOUNDARY") )
  local START_LN="${BOUND_LNUMS[0]}"
  local END_LN="${BOUND_LNUMS[1]}"
  local LN_CNT=
  let -a LN_CNT="$END_LN - $START_LN"
  [ -n "$LN_CNT" ] || return 4$(
    echo "E: bad boundary line numbers: $START_LN..$END_LN" >&2)
  tail -n +"$START_LN" -- "$LOG_FN" | head -n "$LN_CNT" >"$SAVE_BFN".tmp
  local F_HEAD="$(grep -Paxe '\r?' -m 1 -B "$LN_CNT" -- "$SAVE_BFN".tmp \
    | tee "$SAVE_BFN".hdr | tr -d '\r')"
  local CTYPE="$(<<<"$F_HEAD" sed -nre 's~^Content-Type:\s*~~p')"
  local CT_BASE="${CTYPE%%;*}"
  local CT_FEXT=
  case "$CT_BASE" in
    image/gif | \
    image/png | \
    image/jpeg ) CT_FEXT="${CT_BASE#*/}";;
    * ) CT_FEXT=bin;;
  esac
  local C_OFFSET="$(stat -c %s -- "$SAVE_BFN".hdr) + 1"
  let -a C_OFFSET="$C_OFFSET"
  local C_LEN="$(stat -c %s -- "$SAVE_BFN".tmp) - $C_OFFSET - 1"
  let -a C_LEN="$C_LEN"
  tail --bytes=+"$C_OFFSET" -- "$SAVE_BFN".tmp | head --bytes="$C_LEN" \
    >"$SAVE_BFN.$CT_FEXT"
  rm -- "$SAVE_BFN".{tmp,hdr}
  ls -l "$SAVE_BFN".*

  return 0
}


function find_boundary_lnums () {
  local LOG_FN="$1"; shift
  local BOUNDARY="$1"; shift
  <"$LOG_FN" tr -d '\r' | grep -Faxne "$BOUNDARY" -A 1 \
    | grep -aPe '^\d+-'"$CD_FILE_RGX" -m 1 -A 2 \
    | grep -oPe '^\d+[:\-]' | tr '-' ' ' | tr -d ':\n'
}









[ "$1" == --lib ] && return 0; extract_file_upload "$@"; exit $?
