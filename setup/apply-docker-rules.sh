#!/bin/bash
iptables -F DOCKER-USER
iptables -A DOCKER-USER -i eth0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A DOCKER-USER -i docker0 -o docker0 -j ACCEPT
iptables -A DOCKER-USER -i eth0 -m limit --limit 5/min -j LOG --log-prefix 'DOCKER-DROP: ' --log-level 4
iptables -A DOCKER-USER -i eth0 -j DROP
iptables -A DOCKER-USER -j RETURN
ok