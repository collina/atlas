#!/bin/bash

source log.sh

# The following exit relays in Turkey are probed:
# https://atlas.torproject.org/#details/12D3C597E5EE08F2A34EECE19707CB42C56F999B
# https://atlas.torproject.org/#details/1A4A492676A8F548415EB6C77488C144AFC4A942
# https://atlas.torproject.org/#details/633DD5987AF93EF195FCB328450ADA80E1106D06
# https://atlas.torproject.org/#details/68DC0C98B6A8F442D886F308406E180EF5F671C9
# https://atlas.torproject.org/#details/8CC6C62E1A0F5D4EC887013FD35EE11EBBB3B6EE

exit_relays=(
	12D3C597E5EE08F2A34EECE19707CB42C56F999B:6000
	1A4A492676A8F548415EB6C77488C144AFC4A942:6001
	633DD5987AF93EF195FCB328450ADA80E1106D06:6002
	68DC0C98B6A8F442D886F308406E180EF5F671C9:6003
	8CC6C62E1A0F5D4EC887013FD35EE11EBBB3B6EE:6004
)

for exit_relay in "${exit_relays[@]}"
do
	exit_relay=(${exit_relay//:/ })
	fingerprint=${exit_relay[0]}
	port=${exit_relay[1]}

	log "Now probing exit relay ${fingerprint} using SOCKS port ${port}." >> "${fingerprint}.log"

	export TORSOCKS_CONF_FILE="${exit_relay}.torsocks.conf"

	# Make sure that we are actually the right exit relay.
	log "Exit relay ${fingerprint} has IP address $(torsocks wget -qO- http://ano.nymity.ch/myip.php)." >> "${fingerprint}.log" 2>&1

	# DNS test.
	log "Exit relay ${fingerprint} resolves www.twitter.com to $(tor-resolve www.twitter.com 127.0.0.1:${port})." >> "${fingerprint}.log" 2>&1
	log "Exit relay ${fingerprint} resolves www.youtube.com to $(tor-resolve www.youtube.com 127.0.0.1:${port})." >> "${fingerprint}.log" 2>&1

	# X.509 certificate test.
	log "Getting X.509 certificate for twitter.com:443:" >> "${fingerprint}.log"
	log "$(torsocks openssl s_client -showcerts -connect twitter.com:443 </dev/null)" >> "${fingerprint}.log" 2>&1
	log "Getting X.509 certificate for www.youtube.com:443:" >> "${fingerprint}.log"
	log "$(torsocks openssl s_client -showcerts -connect www.youtube.com:443 </dev/null)" >> "${fingerprint}.log" 2>&1

	# HTTP test.
	log "Getting index page for https://twitter.com:" >> "${fingerprint}.log"
	log "$(torsocks wget -qO- https://twitter.com | base64)" >> "${fingerprint}.log" 2>&1
	log "Getting index page for https://www.youtube.com:" >> "${fingerprint}.log"
	log "$(torsocks wget -qO- https://www.youtube.com | base64)" >> "${fingerprint}.log" 2>&1
done
