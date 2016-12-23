# Portanoia
A tool that sets a honeypot port and runs a command against every IP that connects to it.

**Note:** I seriously doubt this code is efficient enough to be used on production, but it works great when you are at cons and don't want to be bothered by nosy attendees

**UPDATE:** I was thinking about it and I think by using concurrency via Goroutines this could actually be used on productions since the response command wont hang the initial program.  Also playing with ways on how to make the TCP listener better by dropping inbound requests.

**UPDATE 2:** By handling TCP connections and the act of immediately dropping them immediately (Well after a full connection, might write own TCP listen for a little more speed) in another Goroutine I think this could scale even better, I'm wondering how well this would do again thousands of concurrent connections.

**UPDATE 3:** Tested with some bechtesting software and ran into issues with max file descriptors.  Added a semaphore to keep file descriptors down and reasonable.  This thread lock is set as a constant @ 50.  This is shared between the TCP listener and command executor.

# Usage
Must be ran as root due to raw packets
```
portanoia -p 1337 -c "iptables -A INPUT -s [SRC_IP] -j DROP"
# OR
portanoia -p 1337 -c "iptables -A INPUT -s [SRC_IP] -j DROP && echo connection attempt from [SRC_IP] blocking | espeak"
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

![Espeak with portanoia in action](https://raw.githubusercontent.com/0x4445565A/portanoia/master/_portanoia.png)
