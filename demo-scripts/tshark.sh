. demo-scripts/demo-magic/demo-magic.sh

DEMO_PROMPT="${GREEN}➜ ${CYAN}\W "

clear

pei 'tshark -o "tls.desegment_ssl_records: TRUE" -o "tls.desegment_ssl_application_data: TRUE" -o "tls.keylog_file: $PWD/keylog.txt" -i lo -Px -O quic -Y "udp.port == 5556"'

p ""
