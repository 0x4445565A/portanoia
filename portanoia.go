package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/fatih/color"
)

const (
	DEST = "DEST"
	SRC  = "SRC"
)

var (
	listen_port int
	command     string
	viewToken   bool
	red         func(string, ...interface{})
	bold        func(string, ...interface{})
)

type Packet struct {
	src_ip    []byte
	dest_ip   []byte
	dest_port int
	src_port  int
}

func (p *Packet) compareIP(packet_ip string, cmp_ip []byte) bool {
	switch packet_ip {
	case DEST:
		return bytes.Equal(p.dest_ip, cmp_ip)
	case SRC:
		return bytes.Equal(p.src_ip, cmp_ip)
	default:
		return false
	}
}

func (p *Packet) ipToString(packet_ip string) string {
	var b []byte
	switch packet_ip {
	case DEST:
		b = p.dest_ip
	case SRC:
		b = p.src_ip
	default:
		b = p.src_ip
	}
	if len(b) != 4 {
		return "127.0.0.1"
	}
	return strconv.Itoa(int(b[0])) + "." + strconv.Itoa(int(b[1])) + "." + strconv.Itoa(int(b[2])) + "." + strconv.Itoa(int(b[3]))
}

func (p *Packet) sameSrc() bool {
	return bytes.Equal(p.dest_ip, p.src_ip)
}

func intToIp(n ...int) []byte {
	b := make([]byte, len(n))
	for i, v := range n {
		b[i] = byte(v)
	}
	return b
}

func main() {
	red = color.New(color.FgRed).Add(color.Bold).PrintfFunc()
	bold = color.New(color.FgWhite).Add(color.Bold).PrintfFunc()
	flag.IntVar(&listen_port, "p", 1337, "port to listen on for honey pot")
	flag.StringVar(&command, "c", "echo [SRC_IP] connected to [DEST_IP]:[DEST_PORT] >> out", "command to use when the port is triggered")
	flag.BoolVar(&viewToken, "t", false, "if used the program will output avaible tokens for the -c flag")
	flag.Parse()

	if viewToken {
		viewTokens()
	}

	bold("Port: ")
	fmt.Printf("%d\n", listen_port)
	bold("Command: ")
	fmt.Printf("%s\n", command)

	l := openPort()
	defer l.Close()
	captureTraffic()
}

func openPort() net.Listener {
	l, err := net.Listen("tcp", ":"+strconv.Itoa(listen_port))
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	return l
}

func captureTraffic() {
	fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	f := os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd))

	for {
		buf := make([]byte, 1024)
		_, err := f.Read(buf)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		p := Packet{
			buf[12:16],
			buf[16:20],
			int(binary.BigEndian.Uint16(buf[22:24])),
			int(binary.BigEndian.Uint16(buf[24:26])),
		}
		if p.dest_port == listen_port && !p.sameSrc() {
			tokens := createTokens(p)
			cmd := command
			for k, v := range tokens {
				cmd = strings.Replace(cmd, k, v, -1)
			}
			red("Connection: ")
			fmt.Println(p.ipToString(SRC), "@", p.dest_ip, ":", p.dest_port)
			bold("Executing: ")
			fmt.Println(cmd)
			_, err := exec.Command("sh", "-c", cmd).Output()
			if err != nil {
				fmt.Println("Error Executing command:", err.Error())
				os.Exit(1)
			}
		}
	}
}

func createTokens(p Packet) map[string]string {
	return map[string]string{
		"[DEST_IP]":     p.ipToString(DEST),
		"[SRC_IP]":      p.ipToString(SRC),
		"[DEST_PORT]":   strconv.Itoa(p.dest_port),
		"[SRC_PORT]":    strconv.Itoa(p.src_port),
		"[LISTEN_PORT]": strconv.Itoa(listen_port),
	}
}

func viewTokens() {
	bold("Below are the availble tokens\n")
	tokens := createTokens(Packet{})
	for k, _ := range tokens {
		fmt.Println(k)
	}
	bold("\n\nBlocking via IPTables\n")
	fmt.Printf("iptables -A INPUT -s [SRC_IP] -j DROP\n")
	bold("Logging to file\n")
	fmt.Printf("echo [SRC_IP] connected to [DEST_IP]:[DEST_PORT] >> out.txt\n")
	os.Exit(0)
}
