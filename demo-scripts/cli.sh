. demo-scripts/demo-magic/demo-magic.sh

DEMO_PROMPT="${GREEN}➜ ${CYAN}\W "

clear

TYPE_SPEED=20

export SSLKEYLOGFILE=$PWD/keylog.txt
pei "export SSLKEYLOGFILE=$PWD/keylog.txt"

export G_MESSAGES_DEBUG=echo
pei "export G_MESSAGES_DEBUG=echo"

pe "_build/cli localhost 5556 credentials/ca.pem"

pei "_build/cli --coalescing 3 localhost 5556 credentials/ca.pem"

pei "_build/cli --streams 3 localhost 5556 credentials/ca.pem"

p ""
