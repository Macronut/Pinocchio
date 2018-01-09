package main

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"strconv"

	"./dns"
)

type ProxyInfo struct {
	Method   int
	AddrList []net.TCPAddr
	Password string
}

type DNSInfo struct {
	Method   int
	AddrList []net.UDPAddr
	Proxy    *ProxyInfo
}

var DNSMap map[string]DNSInfo
var ProxyMap map[string]ProxyInfo
var DNSCacheA map[string][]byte
var DNSCacheAAAA map[string][]byte

func handleLoadConfig(path string) {
	addrlist := make([]net.UDPAddr, 1)
	serverAddr, _ := net.ResolveUDPAddr("udp", "8.8.8.8:53")
	addrlist[0] = *serverAddr
	DNSMap["\x03www\x06google\x03com\x00"] = DNSInfo{dns.TypeA, addrlist, nil}
	return
}

type DNSClient struct {
	ID   uint16
	Addr *net.UDPAddr
}

func handleDNSForward(response []byte, serverAddr *net.UDPAddr, client *net.UDPConn, clientAddr *net.UDPAddr) {
	srcAddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	server, err := net.DialUDP("udp", srcAddr, serverAddr)
	if err != nil {
		log.Println(err)
		return
	}
	defer server.Close()
	_, err = server.Write(response)

	data := make([]byte, 1024)
	_, _, err = server.ReadFromUDP(data)
	if err != nil {
		log.Println(err)
		return
	}

	question, _ := dns.UnpackQuestion(data[12:])

	qname := string(question.QName)

	if question.QType == dns.TypeA {
		log.Println(question.QType)
		DNSCacheA[qname] = data
	} else if question.QType == dns.TypeAAAA {
		log.Println(question.QType)
		DNSCacheAAAA[qname] = data
	}

	//binary.BigEndian.PutUint16(data, id)
	_, err = client.WriteToUDP(data, clientAddr)
}

func handleDNSServer(client *net.UDPConn) {
	data := make([]byte, 512)
	serverAddr, err := net.ResolveUDPAddr("udp", "8.8.8.8:53")

	if err != nil {
		log.Println(err)
		return
	}

	for {
		_, clientAddr, err := client.ReadFromUDP(data)
		if err != nil {
			log.Println(err)
			continue
		}
		header, off := dns.UnpackHeader(data)
		id := header.ID
		question, off := dns.UnpackQuestion(data[off:])
		qname := string(question.QName)
		log.Println(qname)
		dnsinfo, ok := DNSMap[qname]
		if ok {
			log.Println(dnsinfo)
			if dnsinfo.Method != 255 && int(question.QType) != dnsinfo.Method {
				client.WriteToUDP(data, clientAddr)
			}
			serverAddr = &dnsinfo.AddrList[0]
		}

		var cache []byte
		ok = false
		if question.QType == dns.TypeA {
			cache, ok = DNSCacheA[qname]
		} else if question.QType == dns.TypeAAAA {
			cache, ok = DNSCacheAAAA[qname]
		}

		if ok {
			binary.BigEndian.PutUint16(cache, id)
			client.WriteToUDP(cache, clientAddr)
		} else {
			go handleDNSForward(data, serverAddr, client, clientAddr)
		}
	}
}

func handleProxy(client net.Conn) {
	if client == nil {
		return
	}
	defer client.Close()

	var b [1024]byte
	n, err := client.Read(b[:])
	if err != nil {
		log.Println(err)
		return
	}

	if b[0] == 0x05 {
		client.Write([]byte{0x05, 0x00})
		n, err = client.Read(b[:])
		var host, port string
		switch b[3] {
		case 0x01:
			host = net.IPv4(b[4], b[5], b[6], b[7]).String()
		case 0x03:
			host = string(b[5 : n-2])
		case 0x04:
			host = net.IP{b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19]}.String()
		}
		port = strconv.Itoa(int(b[n-2])<<8 | int(b[n-1]))

		server, err := net.Dial("tcp", net.JoinHostPort(host, port))
		if err != nil {
			log.Println(err)
			return
		}
		defer server.Close()
		client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		go io.Copy(server, client)
		io.Copy(client, server)
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	//Config
	DNSMap = make(map[string]DNSInfo)
	ProxyMap = make(map[string]ProxyInfo)
	DNSCacheA = make(map[string][]byte)
	DNSCacheAAAA = make(map[string][]byte)
	handleLoadConfig("/etc/pino.conf")
	//DNS
	addr, err := net.ResolveUDPAddr("udp", ":53")
	udpconn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Panic(err)
	}
	defer udpconn.Close()
	go handleDNSServer(udpconn)
	//Proxy
	l, err := net.Listen("tcp", ":1080")
	if err != nil {
		log.Panic(err)
	}

	for {
		client, err := l.Accept()
		if err != nil {
			log.Panic(err)
		}

		go handleProxy(client)
	}
}
