#!/bin/bash
#
# Copyright 2014 Philipp Winter <phw@nymity.ch>

log() {
	local msg="$1"
	echo "[$(date -u --rfc-3339=ns)] ${msg}"
}

err() {
	local msg="$1"
	echo "[$(date -u --rfc-3339=ns)] ${msg}" >&2
}
