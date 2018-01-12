package main

import (
	"bufio"
	"time"
	//"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"./dns"
)

type ProxyInfo struct {
	Type     uint16
	AddrList []net.TCPAddr
	Password string
}

type ServerInfo struct {
	Type     uint16
	AddrList []net.UDPAddr
}

type DNSCache struct {
	A      *dns.Answers
	AAAA   *dns.Answers
	Server *ServerInfo
	Proxy  *ProxyInfo
}

var CacheMap map[string]DNSCache
var ProxyMap map[int32]ProxyInfo
var DefaultServer ServerInfo
var ProxyAddress net.TCPAddr
var NetWorkType int

func handleLoadConfig(path string) error {
	conf, err := os.Open(path)
	if err != nil {
		return err
	}
	defer conf.Close()
	br := bufio.NewReader(conf)
	for {
		line, _, err := br.ReadLine()
		if err == io.EOF {
			break
		}

		if line[0] != '#' {
			config := strings.Split(string(line), "/")
			configType := strings.Split(config[0], "=")
			if len(config) > 1 {
				if configType[0] == "server" {
					addrlist := make([]net.UDPAddr, 0)
					if config[2] != "" {
						for _, addr := range strings.Split(config[2], "|") {
							if strings.HasPrefix(addr, "[") {
								if !strings.Contains(addr, "]:") {
									addr += ":53"
								}
							} else {
								if !strings.Contains(addr, ":") {
									addr += ":53"
								}
							}
							serverAddr, err := net.ResolveUDPAddr("udp", addr)
							if err != nil {
								log.Println(err)
								continue
							}
							addrlist = append(addrlist, *serverAddr)
						}
					}

					QName := dns.PackQName(config[1])
					var AnswerA *dns.Answers = nil
					var AnswerAAAA *dns.Answers = nil
					if configType[1] == "A" {
						AnswerAAAA = &dns.Answers{0, 0, 0, nil}
					} else if configType[1] == "AAAA" {
						AnswerA = &dns.Answers{0, 0, 0, nil}
					}
					if config[1] == "" {
						DefaultServer = ServerInfo{dns.UDP, addrlist}
					} else {
						CacheMap[string(QName)] = DNSCache{
							AnswerA,
							AnswerAAAA,
							&ServerInfo{dns.UDP, addrlist},
							nil,
						}
					}
				} else if configType[0] == "address" {
					AList := []net.IP{}
					AAAAList := []net.IP{}
					QName := dns.PackQName(config[1])

					if config[2] != "" {
						for _, addr := range strings.Split(config[2], "|") {
							var ip net.IP = net.ParseIP(addr)
							if strings.Contains(addr, ":") {
								AAAAList = append(AList, ip)
							} else {
								AList = append(AList, ip)
							}
						}
					}

					var AnswerA dns.Answers = dns.PackAnswers(AList)
					var AnswerAAAA dns.Answers = dns.PackAnswers(AAAAList)

					CacheMap[string(QName)] = DNSCache{
						&AnswerA,
						&AnswerAAAA,
						nil,
						nil,
					}
				}
			} else {
				if configType[0] == "server" {
					addrlist := make([]net.UDPAddr, 0)
					for _, addr := range strings.Split(configType[1], "|") {
						addr += ":53"
						serverAddr, _ := net.ResolveUDPAddr("udp", addr)
						addrlist = append(addrlist, *serverAddr)
					}
					DefaultServer = ServerInfo{dns.UDP, addrlist}
				} else if configType[0] == "proxy" {
					pProxyAddress, _ := net.ResolveTCPAddr("tcp", configType[1])
					ProxyAddress = *pProxyAddress
				}
			}
		}
	}

	return err
}

func handleDNSForward(id uint16, server *net.UDPConn, client *net.UDPConn, clientAddr *net.UDPAddr) {
	defer server.Close()
	//log.Println(response)

	data := make([]byte, 2048)
	server.SetReadDeadline(time.Now().Add(time.Second * 2))
	for {
		//n, _, err := server.ReadFromUDP(data)
		n, err := server.Read(data)
		if err != nil {
			log.Println(err)
			return
		}

		header, offset := dns.UnpackHeader(data)
		id := header.ID
		question, off := dns.UnpackQuestion(data[offset:])
		offset += off
		if header.ID == id {
			_, err = client.WriteToUDP(data[:n], clientAddr)

			qname := string(question.QName)

			//log.Println(data[:n])
			cache, ok := CacheMap[qname]
			answers := dns.Answers{header.ANCount, header.NSCount, header.ARCount, data[offset:n]}
			if !ok {
				cache = DNSCache{nil, nil, nil, nil}
			}
			if question.QType == dns.TypeA {
				cache.A = &answers
				CacheMap[qname] = cache
			} else if question.QType == dns.TypeAAAA {
				cache.AAAA = &answers
				CacheMap[qname] = cache
			}

			//binary.BigEndian.PutUint16(data, id)
			break
		}
	}
}

func CacheLookup(QName []byte) (DNSCache, bool) {
	cache, ok := CacheMap[string(QName)]
	if ok {
		//log.Println(string(QName), cache)
		return cache, ok
	}
	offset := int(QName[0]) + 1
	for i := 0; i < 2; i++ {
		name := "\x00" + string(QName[offset:])
		cache, ok = CacheMap[name]
		if ok {
			log.Println(name, cache)
			return cache, ok
		}
		o := int(QName[offset])
		if o == 0 {
			break
		}
		offset += o + 1
	}

	return cache, ok
}

func handleDNSServer(client *net.UDPConn) {
	data := make([]byte, 512)

	for {
		n, clientAddr, err := client.ReadFromUDP(data)
		if err != nil {
			log.Println(err)
			continue
		}
		header, off := dns.UnpackHeader(data)
		id := header.ID
		question, off := dns.UnpackQuestion(data[off:])

		cache, ok := CacheLookup(question.QName)
		var serverInfo *ServerInfo = nil
		var answers *dns.Answers = nil

		if ok {
			if question.QType == dns.TypeA {
				answers = cache.A
			} else if question.QType == dns.TypeAAAA {
				answers = cache.AAAA
			}
			//log.Println(cache)
			if answers != nil {
				response := dns.PackResponse(data[:n], *answers)
				client.WriteToUDP(response, clientAddr)
				//log.Println(response)
				continue
			}
			serverInfo = cache.Server
		}
		if serverInfo == nil {
			if question.QType == dns.TypeAAAA {
				response := dns.PackResponse(data[:n], dns.Answers{0, 0, 0, nil})
				client.WriteToUDP(response, clientAddr)
				continue
			}
			serverInfo = &DefaultServer
		}

		//srcAddr := net.UDPAddr{IP: net.IPv4zero, Port: 0}
		//server, err := net.DialUDP("udp", &srcAddr, &serverAddr)
		addr, err := net.ResolveUDPAddr("udp", ":0")
		server, err := net.ListenUDP("udp", addr)
		if err != nil {
			log.Println(err)
			continue
		}

		for _, serverAddr := range (*serverInfo).AddrList {

			_, err = server.WriteToUDP(data[:n], &serverAddr)
			if err != nil {
				log.Println(err)
				continue
			}
		}
		go handleDNSForward(id, server, client, clientAddr)
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
	CacheMap = make(map[string]DNSCache)
	ProxyMap = make(map[int32]ProxyInfo)
	NetWorkType = 1
	//err := handleLoadConfig("/etc/pino.conf")
	err := handleLoadConfig("pino.conf")
	if err != nil {
		log.Println(err)
		return
	}
	//DNS
	addr, err := net.ResolveUDPAddr("udp", ":53")
	udpconn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Println(err)
		addr, err = net.ResolveUDPAddr("udp", ":54")
		udpconn, err = net.ListenUDP("udp", addr)
		if err != nil {
			log.Panic(err)
			return
		}
	}
	defer udpconn.Close()
	go handleDNSServer(udpconn)
	//Proxy
	l, err := net.ListenTCP("tcp", &ProxyAddress)
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
