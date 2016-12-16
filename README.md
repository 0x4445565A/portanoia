# Portanoia
A tool that sets a honeypot port and runs a command against every IP that connects to it.

**Note:** I seriously doubt this code is efficient enough to be used on production, but it works great when you are at cons and don't want to be bothered by nosy attendees

# Usage
Must be ran as root due to raw packets
```
portanoia -p 1337 -c "iptables -A INPUT -s [SRC_IP] -j DROP"
```

# Install from Source
```
go get -u github.com/0x4445565a/portanoia
go install github.com/0x4445565a/portanoia
```

# Downloading binary
why would you want to download an unknown binary from github and run it as root?

# Ideas
This was fun but using espeak and portanoia to trigger when connected to.  This results in an alert being spoken over the default audio device.
![Espeak with portanoia in action](https://raw.githubusercontent.com/0x4445565A/portanoia/master/portanoia.png)
