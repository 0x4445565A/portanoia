# Portanoia
A tool that sets a honeypot port and runs a command against every IP that connects to it.

**Note:** I seriously doubt this code is efficient enough to be used on production, but it works great when you are at cons and don't want to be bothered by nosy attendees

# Usage
```
portanoia -p 1337 -c "iptables -A INPUT -s [SRC_IP] -j DROP"
```
