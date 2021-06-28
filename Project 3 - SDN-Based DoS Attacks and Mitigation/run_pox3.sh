set -x
sudo ./pox.py openflow.of_01 \
	--port=6655 pox.forwarding.l3_learning \
	pox.forwarding.Lab3Firewall \
	--l2config="l2firewall.config" \
    --l3config="l3firewall.config" \
	log.level --DEBUG

