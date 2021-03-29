package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var portPtr *int64
var devPtr *string
var commandPtr *string

// Ease of use constants
const (
	DEST = "DEST"
	SRC  = "SRC"
)

func init() {
	portPtr = flag.Int64("port", 1337, "Port to listen with honey pot")
	devPtr = flag.String("dev", "en0", "Device to watch for packet")
	commandPtr = flag.String("cmd", "echo [SRC_IP] connected to [DEST_IP]:[DEST_PORT] >> out", "Command to execute when a connection is found")
	listDevPtr := flag.Bool("list-dev", false, "List all the devices then exit")

	flag.Parse()

	if *listDevPtr {
		devs, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}
		for _, dev := range devs {
			log.Printf("%s: %v", dev.Name, dev.Addresses)
		}
	}
}

func main() {
	threads := 50
	ch := make(chan struct{}, threads)
	for i := 0; i < threads; i++ {
		ch <- struct{}{}
	}

	honeyPotDeviceAtPort(ch, *devPtr, *portPtr)
}

func honeyPotDeviceAtPort(ch chan struct{}, dev string, port int64) {
	l := openPort(port)
	go dropPortConnections(l)
	defer l.Close()

	if handle, err := pcap.OpenLive(dev, 1024, true, pcap.BlockForever); err != nil {
		log.Fatal(err)
	} else if err := handle.SetBPFFilter("port " + strconv.FormatInt(port, 10)); err != nil { // optional
		log.Fatal(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			<-ch
			go handlePacket(ch, packet)
		}
	}
}

func openPort(port int64) net.Listener {
	l, err := net.Listen("tcp", ":"+strconv.FormatInt(port, 10))
	if err != nil {
		log.Fatal(err)
	}
	return l
}

/**
 * Upon connection drop connection.
 */
func dropPortConnections(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Print(err)
		}
		conn.Close()
	}
}

func handlePacket(ch chan struct{}, packet gopacket.Packet) {
	defer func() { ch <- struct{}{} }()

	p := newPacketFromPacket(packet)
	if p.SameSourceDestIP() {
		return
	}
	executeCommand(p)
}

type packet struct {
	DestIP   []byte
	SrcIP    []byte
	DestPort int
	SrcPort  int
}

func (p *packet) SameSourceDestIP() bool {
	return bytes.Equal(p.DestIP, p.SrcIP)
}

func (p *packet) DecBytesToString(foo string) string {
	var b []byte
	switch foo {
	case DEST:
		b = p.DestIP
	case SRC:
		b = p.SrcIP
	}
	// Just a catchall, this shouldn't happen.
	if len(b) != 4 {
		return "127.0.0.1"
	}
	return strconv.FormatInt(int64(b[0]), 10) + "." + strconv.FormatInt(int64(b[1]), 10) + "." + strconv.FormatInt(int64(b[2]), 10) + "." + strconv.FormatInt(int64(b[3]), 10)
}

func newPacketFromPacket(packetSource gopacket.Packet) *packet {
	var networkLayerBuf []byte
	var buf []byte
	p := &packet{}
	layers := packetSource.Layers()

	// Network Layer is layer #2(index 1).
	networkLayer := layers[1]
	if networkLayer != nil {
		networkLayerBuf = networkLayer.LayerContents()
	}

	// Transport Layer is layer #3(index 2) but if we receive a fragment packet attack the transport interface isn't used.
	transportLayer := layers[2]
	if transportLayer != nil {
		buf = transportLayer.LayerContents()
	}

	if len(networkLayerBuf) >= 20 {
		p.DestIP = networkLayerBuf[12:16]
		p.SrcIP = networkLayerBuf[16:20]
	}

	if len(buf) >= 4 {
		p.DestPort = int(binary.BigEndian.Uint16(buf[2:4]))
		p.SrcPort = int(binary.BigEndian.Uint16(buf[0:2]))
	}

	return p
}

func createTokens(p *packet) map[string]string {
	return map[string]string{
		"[DEST_IP]":     p.DecBytesToString(DEST),
		"[SRC_IP]":      p.DecBytesToString(SRC),
		"[DEST_PORT]":   strconv.Itoa(p.DestPort),
		"[SRC_PORT]":    strconv.Itoa(p.DestPort),
		"[LISTEN_PORT]": strconv.FormatInt(int64(*portPtr), 10),
	}
}

/**
 * Replace tokens in command with proper values.
 */
func replaceTokens(p *packet) string {
	tokens := createTokens(p)
	cmd := *commandPtr
	for k, v := range tokens {
		cmd = strings.Replace(cmd, k, v, -1)
	}
	return cmd
}

func executeCommand(p *packet) {
	// Replace tokens with proper values, preserve original command
	cmd := replaceTokens(p)
	// Display command information
	log.Printf("EXECUTING: %s", cmd)
	// Execute the command
	_, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		log.Printf("ERROR EXECUTING: %s", err.Error())
	}
}
