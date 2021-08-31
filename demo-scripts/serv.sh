. demo-scripts/demo-magic/demo-magic.sh

DEMO_PROMPT="${GREEN}➜ ${CYAN}\W "

clear

export G_MESSAGES_DEBUG=echo:ngtcp2
pei "export G_MESSAGES_DEBUG=echo:ngtcp2"

pe "_build/serv localhost 5556 credentials/server-key.pem credentials/server.pem"

p ""
