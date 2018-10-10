package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"./dns"
	"./proxy"
)

type ServerInfo struct {
	Type     uint16
	AddrList []net.UDPAddr
	Option   string
}

type ClientInfo struct {
	ID     uint16
	Time   int64
	Client *net.UDPAddr
	Cache  *DNSCache
}

type DNSCache struct {
	A      *dns.Answers
	AAAA   *dns.Answers
	Server *ServerInfo
	Proxy  *proxy.ProxyInfo
}

type DNSTruth struct {
	Host  string
	Proxy *proxy.ProxyInfo
}

var CacheLock sync.RWMutex
var CacheMap map[string]DNSCache
var ProxyMap map[uint64]*proxy.ProxyInfo
var DefaultServer DNSCache
var ProxyAddress net.TCPAddr
var ProxyClients map[string]bool
var Nose []DNSTruth = []DNSTruth{DNSTruth{"pinocchio", nil}}
var DNSMode int = 0
var DNSMinTTL int = 3600
var LogEnable bool = false
var DNSAddress *net.UDPAddr

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

		if len(line) > 0 && line[0] != '#' {
			config := strings.SplitN(string(line), "/", 4)
			configType := strings.SplitN(config[0], "=", 2)
			if len(config) > 1 {
				if configType[0] == "quote" {
					IP := net.ParseIP(config[1])
					cache, ok := CacheMap[config[2]]
					if IP == nil {
						if ok {
							CacheMap[config[1]] = cache
						} else {
							log.Println(config[1], config[2])
						}
					} else {
						var index uint64
						if IP[0] == 0x00 {
							index = uint64(binary.BigEndian.Uint32(IP[12:16]))
						} else {
							index = binary.BigEndian.Uint64(IP[:8])
						}
						ProxyMap[index] = cache.Proxy
					}
				} else if configType[0] == "server" {
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

					var AnswerA *dns.Answers = nil
					var AnswerAAAA *dns.Answers = nil
					if configType[1] == "A" {
						AnswerAAAA = &dns.NoAnswer
					} else if configType[1] == "AAAA" {
						AnswerA = &dns.NoAnswer
					}

					var option string
					var dnstype uint16 = dns.UDP
					if len(config) > 3 {
						url := strings.SplitN(config[3], "://", 2)
						if len(url) > 1 {
							if url[0] == "https" {
								if url[1] == "dns.google.com/resolve?name=" {
									dnstype = dns.HTTPS
								} else {
									dnstype = dns.DOH
								}
							}
							option = config[3]
						} else {
							option = config[3]
						}
					} else {
						option = ""
					}

					dnsCache := DNSCache{
						AnswerA,
						AnswerAAAA,
						&ServerInfo{dnstype, addrlist, option},
						nil,
					}
					if config[1] == "" {
						DefaultServer = dnsCache
					} else {
						QName := config[1]
						CacheMap[QName] = dnsCache
					}
				} else if configType[0] == "address" {
					AList := []net.IP{}
					AAAAList := []net.IP{}
					QName := config[1]
					var pProxy *proxy.ProxyInfo = nil

					if config[2] != "" {
						for _, addr := range strings.Split(config[2], "|") {
							var ip net.IP = net.ParseIP(addr)
							if strings.Contains(addr, ":") {
								AAAAList = append(AList, ip)
							} else {
								AList = append(AList, ip)
							}
						}
					} else {
						pProxy = &proxy.ProxyInfo{proxy.MOVE, 0, nil, ""}
					}

					var AnswerA dns.Answers = dns.PackAnswers(AList)
					var AnswerAAAA dns.Answers = dns.PackAnswers(AAAAList)

					CacheMap[QName] = DNSCache{
						&AnswerA,
						&AnswerAAAA,
						nil,
						pProxy,
					}
				} else if configType[0] == "proxy" {
					var proxyType uint16 = proxy.Direct
					netInfo := strings.Split(configType[1], ":")
					if netInfo[0] == "socks" {
						proxyType = proxy.Socks5
					} else if netInfo[0] == "socks5" {
						proxyType = proxy.Socks5
					} else if netInfo[0] == "http" {
						proxyType = proxy.HTTP
					} else if netInfo[0] == "6to4" {
						proxyType = proxy.IPv6to4
					} else if netInfo[0] == "4to6" {
						proxyType = proxy.IPv4to6
					} else if netInfo[0] == "bind" {
						proxyType = proxy.BIND
					} else if netInfo[0] == "bindtfo" {
						proxyType = proxy.BINDTFO
					} else if netInfo[0] == "move" {
						proxyType = proxy.MOVE
					} else if netInfo[0] == "movetfo" {
						proxyType = proxy.MOVETFO
					} else if netInfo[0] == "ttl" {
						proxyType = proxy.TTL
					} else if netInfo[0] == "ttls" {
						proxyType = proxy.TTLS
					} else if netInfo[0] == "tfo" {
						proxyType = proxy.TFO
					}

					var mss uint16 = 0
					if len(netInfo) > 1 {
						n, _ := strconv.Atoi(configType[1][4:])
						mss = uint16(n)
					}

					addrlist := make([]net.TCPAddr, 0)
					if config[2] != "" {
						for _, addr := range strings.Split(config[2], "|") {
							if strings.HasPrefix(addr, "[") {
								if !strings.Contains(addr, "]:") {
									addr += ":0"
								}
							} else {
								if !strings.Contains(addr, ":") {
									addr += ":0"
								}
							}
							serverAddr, err := net.ResolveTCPAddr("tcp", addr)
							if err != nil {
								log.Println(err)
								continue
							}
							addrlist = append(addrlist, *serverAddr)
						}
					}

					var option string
					if len(config) > 3 {
						option = config[3]
					} else {
						option = ""
					}

					IP := net.ParseIP(config[1])
					if IP == nil {
						host := config[1]
						cache, ok := CacheMap[host]
						if ok {
							CacheMap[host] = DNSCache{
								cache.A,
								cache.AAAA,
								cache.Server,
								&proxy.ProxyInfo{proxyType, mss, addrlist, option},
							}
						} else {
							CacheMap[host] = DNSCache{nil, nil, nil,
								&proxy.ProxyInfo{proxyType, mss, addrlist, option},
							}
						}
					} else {
						var index uint64
						if IP[0] == 0x00 {
							index = uint64(binary.BigEndian.Uint32(IP[12:16]))
						} else {
							index = binary.BigEndian.Uint64(IP[:8])
						}
						ProxyMap[index] = &proxy.ProxyInfo{proxyType, mss, addrlist, option}
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
					DefaultServer = DNSCache{
						nil,
						nil,
						&ServerInfo{dns.UDP, addrlist, ""},
						nil,
					}
				} else if configType[0] == "port" {
					DNSAddress, err = net.ResolveUDPAddr("udp", ":"+configType[1])
					if err != nil {
						log.Println(configType[1])
						continue
					}
				} else if configType[0] == "proxy" {
					pProxyAddress, err := net.ResolveTCPAddr("tcp", configType[1])
					if err != nil {
						log.Println(configType[1])
						continue
					}
					ProxyAddress = *pProxyAddress
				} else if configType[0] == "clients" {
					for _, addr := range strings.Split(configType[1], "|") {
						ProxyClients[addr] = true
					}
				}
			}
		}
	}

	return err
}

func handleDNSForward(server *net.UDPConn, client *net.UDPConn, clientsList *[]*ClientInfo, idMask uint16) {
	defer server.Close()

	data := make([]byte, 2048)
	var indexWaiting uint16 = 0

	for {
		n, err := server.Read(data)
		if err != nil {
			log.Println(err)
			continue
		}

		if n < 12 {
			continue
		}
		header, offset := dns.UnpackHeader(data)

		index := header.ID ^ idMask
		clientInfo := (*clientsList)[index]
		if clientInfo != nil {
			binary.BigEndian.PutUint16(data[:2], clientInfo.ID)
			_, err = client.WriteToUDP(data[:n], clientInfo.Client)

			question, off := dns.UnpackQuestion(data[offset:n])
			if (question.QType != dns.TypeA) && (question.QType != dns.TypeAAAA) {
				(*clientsList)[header.ID] = nil
				continue
			}
			offset += off

			qname := question.QName
			adata := make([]byte, n-offset)
			copy(adata, data[offset:n])
			answers := dns.Answers{time.Now().Unix() + int64(DNSMinTTL), header.ANCount, header.NSCount, header.ARCount, adata}
			var cache DNSCache
			if clientInfo.Cache == nil {
				cache = DNSCache{nil, nil, nil, nil}
			} else {
				cache = *clientInfo.Cache
			}
			if question.QType == dns.TypeA {
				cache.A = &answers
				CacheLock.Lock()
				CacheMap[qname] = cache
				CacheLock.Unlock()
			} else {
				cache.AAAA = &answers
				CacheLock.Lock()
				CacheMap[qname] = cache
				CacheLock.Unlock()
			}

			(*clientsList)[index] = nil

			//GC
			for index != indexWaiting {
				if (*clientsList)[index] == nil {
					indexWaiting++
					continue
				}
				if time.Now().Unix()-(*clientsList)[index].Time > 5 {
					(*clientsList)[index] = nil
					indexWaiting++
					continue
				}
				break
			}
		}
	}
}

func handleUDPForward(id uint16, curCache *DNSCache, server *net.UDPConn, client *net.UDPConn, clientAddr *net.UDPAddr) {
	defer server.Close()

	data := make([]byte, 2048)
	server.SetReadDeadline(time.Now().Add(time.Second * 5))
	for {
		//n, _, err := server.ReadFromUDP(data)
		n, err := server.Read(data)
		if err != nil {
			if LogEnable {
				log.Println(err)
			}
			return
		}

		if n < 12 {
			continue
		}
		header, offset := dns.UnpackHeader(data)

		if header.ID == id {
			var cache DNSCache
			if curCache == nil {
				cache = DNSCache{nil, nil, nil, nil}
			} else {
				cache = *curCache
			}
			if cache.Proxy == nil {
				_, err = client.WriteToUDP(data[:n], clientAddr)
				question, off := dns.UnpackQuestion(data[offset:n])
				if (question.QType != dns.TypeA) && (question.QType != dns.TypeAAAA) {
					continue
				}
				offset += off

				qname := string(question.QName)
				//cache, ok := CacheMap[qname]
				adata := make([]byte, n-offset)
				copy(adata, data[offset:n])
				answers := dns.Answers{time.Now().Unix() + int64(DNSMinTTL), header.ANCount, header.NSCount, header.ARCount, adata}

				if question.QType == dns.TypeA {
					cache.A = &answers
					CacheLock.Lock()
					CacheMap[qname] = cache
					CacheLock.Unlock()
				} else {
					cache.AAAA = &answers
					CacheLock.Lock()
					CacheMap[qname] = cache
					CacheLock.Unlock()
				}
				//binary.BigEndian.PutUint16(data, id)
			} else {
				question, off := dns.UnpackQuestion(data[offset:n])
				if (question.QType != dns.TypeA) && (question.QType != dns.TypeAAAA) {
					continue
				}
				offset += off

				cache.Proxy.AddrList = dns.UnPackAnswers(data[offset:n], int(header.ANCount))
				answers := AddLie(question, cache)
				response := dns.QuickResponse(data[:offset], *answers)
				client.WriteToUDP(response, clientAddr)
			}
			return
		}
	}
}

func handleHTTPSForward(header dns.Header, question dns.Question, curCache *DNSCache,
	client *net.UDPConn, clientAddr *net.UDPAddr) {
	IPList, err := dns.HTTPSLookup(question.QName, question.QType)
	if err != nil {
		log.Println(err)
		return
	}
	answers := dns.PackAnswersTTL(IPList)
	response := dns.PackResponse(header, question, answers)
	client.WriteToUDP(response, clientAddr)

	qname := string(question.QName)
	var cache DNSCache
	if curCache == nil {
		cache = DNSCache{nil, nil, nil, nil}
	} else {
		cache = *curCache
	}
	if question.QType == dns.TypeA {
		cache.A = &answers
		CacheLock.Lock()
		CacheMap[qname] = cache
		CacheLock.Unlock()
	} else if question.QType == dns.TypeAAAA {
		cache.AAAA = &answers
		CacheLock.Lock()
		CacheMap[qname] = cache
		CacheLock.Unlock()
	}
}

func handleDOHForward(header dns.Header, question dns.Question, curCache *DNSCache,
	client *net.UDPConn, clientAddr *net.UDPAddr) {
	request := dns.PackRequest(header, question)
	//binary.BigEndian.PutUint16(request, 0x0010)

	response, err := dns.DoHLookup(request, curCache.Server.Option)
	if err != nil {
		log.Println(err)
		return
	}

	header, offset := dns.UnpackHeader(response)
	if offset > len(response) {
		log.Println(question.QName, response)
		return
	}
	question, off := dns.UnpackQuestion(response[offset:])
	offset += off

	var cache DNSCache = *curCache
	if cache.Proxy == nil {
		client.WriteToUDP(response, clientAddr)
		answers := dns.Answers{time.Now().Unix() + int64(DNSMinTTL), header.ANCount, header.NSCount, header.ARCount, response[offset:]}
		if question.QType == dns.TypeA {
			cache.A = &answers
			CacheLock.Lock()
			CacheMap[question.QName] = cache
			CacheLock.Unlock()
		} else if question.QType == dns.TypeAAAA {
			cache.AAAA = &answers
			CacheLock.Lock()
			CacheMap[question.QName] = cache
			CacheLock.Unlock()
		}
	} else {
		cache.Proxy.AddrList = dns.UnPackAnswers(response[offset:], int(header.ANCount))
		answers := AddLie(question, cache)
		response := dns.QuickResponse(request, *answers)
		client.WriteToUDP(response, clientAddr)
	}
}

func CacheLookup(qname string) DNSCache {
	CacheLock.RLock()
	defer CacheLock.RUnlock()
	cache, ok := CacheMap[qname]
	if ok {
		return cache
	}

	offset := 0
	for i := 0; i < 2; i++ {
		off := strings.Index(qname[offset:], ".")
		if off == -1 {
			return DefaultServer
		}
		offset += off
		cache, ok = CacheMap[qname[offset:]]
		if ok {
			if LogEnable {
				log.Println(qname, cache)
			}
			return cache
		}
		offset++
	}

	return DefaultServer
}

func AddLie(question dns.Question, cache DNSCache) *dns.Answers {
	var answers *dns.Answers = nil
	if DNSMode == 0 {
		if question.QType == dns.TypeAAAA {
			newID := len(Nose)
			lie := dns.BuildLie(newID, question.QType)
			answers = &lie
			cache.AAAA = answers
			cache.A = &dns.NoAnswer
			Nose = append(Nose, DNSTruth{question.QName, cache.Proxy})
			if LogEnable {
				log.Println(question.QName, cache.Proxy)
			}

			CacheLock.Lock()
			CacheMap[question.QName] = cache
			CacheLock.Unlock()
			return answers
		} else {
			return &dns.NoAnswer
		}
	} else if DNSMode == 4 {
		if question.QType == dns.TypeA {
			newID := len(Nose)
			lie := dns.BuildLie(newID, question.QType)
			answers = &lie
			cache.AAAA = &dns.NoAnswer
			cache.A = answers
			Nose = append(Nose, DNSTruth{question.QName, cache.Proxy})
			if LogEnable {
				log.Println(question.QName, cache.Proxy)
			}

			CacheLock.Lock()
			CacheMap[question.QName] = cache
			CacheLock.Unlock()
			return answers
		} else {
			return &dns.NoAnswer
		}
	}
	return &dns.NoAnswer
}

func NSLookup(qname string, qtype uint16, cache *DNSCache) []net.TCPAddr {
	var header dns.Header
	header.ID = 0
	header.Flag = 0x0100
	header.QDCount = 1
	header.ANCount = 0
	header.NSCount = 0
	header.ARCount = 0

	var question dns.Question
	question.QName = qname
	question.QType = qtype
	question.QClass = 0x01

	var curCache DNSCache
	if cache == nil {
		curCache = CacheLookup(question.QName)
		cache = &curCache
	}

	var answers *dns.Answers = nil
	if qtype == dns.TypeA {
		answers = cache.A
	} else if qtype == dns.TypeAAAA {
		answers = cache.AAAA
	}

	if answers == nil {
		if cache.Server != nil {
			request := dns.PackRequest(header, question)
			data := make([]byte, 2048)

			switch (*cache.Server).Type {
			case dns.UDP:
				addr, err := net.ResolveUDPAddr("udp", ":0")
				server, err := net.ListenUDP("udp", addr)
				if err != nil {
					log.Println(err)
					return nil
				}

				for _, serverAddr := range (*cache.Server).AddrList {
					_, err = server.WriteToUDP(request, &serverAddr)
					if err != nil {
						log.Println(err)
						return nil
					}
				}
				server.SetReadDeadline(time.Now().Add(time.Second * 5))

				for {
					n, err := server.Read(data)
					if err != nil {
						log.Println(err)
						return nil
					}

					if n < 12 {
						continue
					}
					header, offset := dns.UnpackHeader(data)

					if header.ID == 0 {
						question, off := dns.UnpackQuestion(data[offset:n])
						offset += off

						if cache.Proxy == nil {
							qname := string(question.QName)
							adata := make([]byte, n-offset)
							copy(adata, data[offset:n])
							answers := dns.Answers{
								time.Now().Unix() + int64(DNSMinTTL),
								header.ANCount, header.NSCount,
								header.ARCount, adata}
							if question.QType == dns.TypeA {
								cache.A = &answers
								CacheLock.Lock()
								CacheMap[qname] = *cache
								CacheLock.Unlock()
							} else if question.QType == dns.TypeAAAA {
								cache.AAAA = &answers
								CacheLock.Lock()
								CacheMap[qname] = *cache
								CacheLock.Unlock()
							} else {
								continue
							}
						}

						return dns.UnPackAnswers(data[offset:n], int(header.ANCount))
					}
				}
			case dns.TCP:
				//TODO
			case dns.HTTPS:
				IPList, _ := dns.HTTPSLookup(question.QName, question.QType)
				return IPList
			case dns.DOH:
				response, err := dns.DoHLookup(request, cache.Server.Option)
				if err != nil {
					return nil
				}
				header, offset := dns.UnpackHeader(response)
				question, off := dns.UnpackQuestion(response[offset:])
				offset += off

				if cache.Proxy == nil {
					qname := string(question.QName)
					adata := make([]byte, len(response)-offset)
					copy(adata, response[offset:])
					answers := dns.Answers{time.Now().Unix() + int64(DNSMinTTL),
						header.ANCount, header.NSCount,
						header.ARCount, adata}
					if question.QType == dns.TypeA {
						cache.A = &answers
						CacheLock.Lock()
						CacheMap[qname] = *cache
						CacheLock.Unlock()
					} else if question.QType == dns.TypeAAAA {
						cache.AAAA = &answers
						CacheLock.Lock()
						CacheMap[qname] = *cache
						CacheLock.Unlock()
					} else {
						return nil
					}
				}

				return dns.UnPackAnswers(response[offset:], int(header.ANCount))
			}
		}
	} else {
		return dns.UnPackAnswers(answers.Answers, int(answers.ANCount))
	}

	return nil
}

func handleDNSServer(client *net.UDPConn, randport bool) {
	data := make([]byte, 512)

	var server *net.UDPConn = nil
	var clientsList []*ClientInfo
	var index uint16 = 0
	var idMask uint16 = uint16(time.Now().UnixNano() & 0xFFFF)

	if randport == false {
		addr, err := net.ResolveUDPAddr("udp", ":0")
		server, err = net.ListenUDP("udp", addr)

		if err != nil {
			log.Println(err)
			return
		}
		clientsList = make([]*ClientInfo, 65536)
		go handleDNSForward(server, client, &clientsList, idMask)
	}

	for {
		n, clientAddr, err := client.ReadFromUDP(data)
		if err != nil {
			log.Println(err)
			continue
		}

		Now := time.Now()
		if n < 12 {
			continue
		}
		header, off := dns.UnpackHeader(data)
		id := header.ID
		if header.QDCount == 0 {
			continue
		}
		question, off := dns.UnpackQuestion(data[off:n])
		if off == 0 {
			log.Println(question.QName, "ERROR")
			continue
		}

		cache := CacheLookup(question.QName)

		var answers *dns.Answers = nil
		if question.QType == dns.TypeA {
			answers = cache.A
		} else if question.QType == dns.TypeAAAA {
			answers = cache.AAAA
		}

		if answers != nil {
			response := dns.QuickResponse(data[:n], *answers)
			client.WriteToUDP(response, clientAddr)
			if Now.Unix() < answers.Expires {
				continue
			}
		}

		if cache.Server != nil {
			if LogEnable {
				log.Println(question.QName, question.QType, time.Since(Now))
			}

			switch (*cache.Server).Type {
			case dns.UDP:
				if randport {
					addr, err := net.ResolveUDPAddr("udp", ":0")
					server, err := net.ListenUDP("udp", addr)
					if err != nil {
						log.Println(err)
						continue
					}

					for _, serverAddr := range (*cache.Server).AddrList {
						_, err = server.WriteToUDP(data[:n], &serverAddr)
						if err != nil {
							log.Println(err)
							continue
						}
					}
					go handleUDPForward(id, &cache, server, client, clientAddr)
				} else {
					clientsList[index] = &ClientInfo{id, time.Now().Unix(), clientAddr, &cache}
					binary.BigEndian.PutUint16(data[:], index^idMask)
					for _, serverAddr := range (*cache.Server).AddrList {
						_, err = server.WriteToUDP(data[:n], &serverAddr)
						if err != nil {
							log.Println(err)
							continue
						}
					}
					index++
				}
				continue
			case dns.TCP:
				//TODO
			case dns.HTTPS:
				go handleHTTPSForward(header, question, &cache, client, clientAddr)
				continue
			case dns.DOH:
				go handleDOHForward(header, question, &cache, client, clientAddr)
				continue
			}
		}

		if cache.Proxy != nil {
			answers = AddLie(question, cache)
			response := dns.QuickResponse(data[:n], *answers)
			client.WriteToUDP(response, clientAddr)
		}
	}
}

func handleProxy(client *net.TCPConn) {
	if client == nil {
		return
	}
	defer client.Close()

	var host string
	port := 0
	var Proxy *proxy.ProxyInfo = nil
	pDSTAddr, err := proxy.GetOriginalDST(client)
	if err != nil {
		log.Println(err)
		return
	}
	if pDSTAddr != nil {
		IP := []byte(pDSTAddr.IP)
		if IP[0] == 0x20 && IP[1] == 0x00 {
			index := int(IP[12])<<24 | int(IP[13])<<16 | int(IP[14])<<8 | int(IP[15])
			if index >= len(Nose) {
				return
			}
			truth := Nose[index]
			host = truth.Host
			port = pDSTAddr.Port
			Proxy = truth.Proxy
			pDSTAddr = nil
			if LogEnable {
				log.Println(host, port)
			}
		} else if IP[0] == 100 && IP[1] == 64 {
			index := int(IP[2])<<8 | int(IP[3])
			if index >= len(Nose) {
				return
			}
			truth := Nose[index]
			host = truth.Host
			port = pDSTAddr.Port
			Proxy = truth.Proxy
			pDSTAddr = nil
			if LogEnable {
				log.Println(host, port)
			}
		} else {
			var index uint64
			if len(IP) == 4 {
				index = uint64(binary.BigEndian.Uint32(IP[:4]))
			} else {
				index = binary.BigEndian.Uint64(IP[:8])
			}
			var ok bool
			Proxy, ok = ProxyMap[index]
			if ok {
				port = pDSTAddr.Port
				if LogEnable {
					log.Println(pDSTAddr)
				}
			} else {
				log.Println(pDSTAddr, ":Unknow IP")
				return
			}
		}
	} else {
		if len(ProxyClients) > 0 {
			RemoteAddr := client.RemoteAddr()
			RemoteTCPAddr, _ := net.ResolveTCPAddr(RemoteAddr.Network(), RemoteAddr.String())
			strIP := RemoteTCPAddr.IP.String()
			_, ok := ProxyClients[strIP]
			if !ok {
				fmt.Println(strIP, "Forbidden")
				return
			}
		}

		var b [1460]byte
		n, err := client.Read(b[:])
		if err != nil {
			return
		}
		switch b[0] {
		case 0x05:
			client.Write([]byte{0x05, 0x00})
			n, err = client.Read(b[:])
			if err != nil {
				return
			}
			switch b[3] {
			case 0x01:
				index := uint64(binary.BigEndian.Uint32(b[4:8]))
				port = int(b[n-2])<<8 | int(b[n-1])
				pDSTAddr = &net.TCPAddr{b[4:8], port, ""}
				var ok bool
				Proxy, ok = ProxyMap[index]
				if !ok {
					Proxy = nil
				}
				if LogEnable {
					fmt.Println("SOCKS", client.RemoteAddr(), pDSTAddr, Proxy)
				}
			case 0x03:
				host = string(b[5 : n-2])
				port = int(b[n-2])<<8 | int(b[n-1])
				cache := CacheLookup(host)
				Proxy = cache.Proxy
				if Proxy != nil {
					if len(Proxy.AddrList) == 0 {
						addrlist := NSLookup(host, 1, &cache)
						if addrlist == nil {
							return
						}
						Proxy.AddrList = addrlist
						cache.Proxy = Proxy
						CacheLock.Lock()
						CacheMap[host] = cache
						CacheLock.Unlock()
					}
				}
				if LogEnable {
					fmt.Println("SOCKS", host, port, Proxy)
				}
			case 0x04:
				index := binary.BigEndian.Uint64(b[4:12])
				port = int(b[n-2])<<8 | int(b[n-1])
				pDSTAddr = &net.TCPAddr{b[4:20], port, ""}
				var ok bool
				Proxy, ok = ProxyMap[index]
				if !ok {
					log.Println(pDSTAddr, ":Unknow IP")
					return
				}
				if LogEnable {
					fmt.Println("SOCKS", pDSTAddr)
				}
			}
			client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		case 0x16:
			host = proxy.GetSNI(b[:n])
			if len(host) > 0 {
				port = 443
				cache := CacheLookup(host)
				Proxy = cache.Proxy
				if LogEnable {
					fmt.Println("SNI", host, port)
				}
			} else {
				return
			}
		case 0x43:
			request := string(b[:n])
			if request[:7] == "CONNECT" {
				hostend := strings.Index(request[8:], " ")
				if hostend > 0 {
					host = request[8 : hostend+8]
					ipv6end := strings.Index(host, "]")
					ipv6end++
					portstart := strings.Index(host[ipv6end:], ":")
					if portstart > -1 {
						portstart += ipv6end
						port, err = strconv.Atoi(host[portstart+1:])
						if err != nil {
							log.Println(err)
							return
						}
						host = host[:portstart]
					} else {
						port = 80
					}

					cache := CacheLookup(host)
					Proxy = cache.Proxy
					if LogEnable {
						fmt.Println("CONNECT", host, port)
					}
					client.Write([]byte("HTTP/1.1 200 Tunnel established\r\n\r\n"))
				}
			} else {
				return
			}
		case 0x47:
			request := string(b[:n])
			if request[:4] == "GET " {
				if LogEnable {
					fmt.Println("GET", host, port)
				}
				proxy.HTTPProxy(client, request)
			} else {
				return
			}
		case 0x48:
			request := string(b[:n])
			if request[:4] == "HEAD" {
				if LogEnable {
					fmt.Println("HEAD", host, port)
				}
				proxy.HTTPProxy(client, request)
			} else {
				return
			}
		case 0x50:
			request := string(b[:n])
			if request[:4] == "POST" {
				if LogEnable {
					fmt.Println("POST", host, port)
				}
				proxy.HTTPProxy(client, request)
			} else {
				return
			}
		default:
			return
		}
	}

	if Proxy == nil {
		if DNSAddress.Port == 0 {
			addrlist := NSLookup(host, 1, nil)
			proxy.ProxyAddress(client, addrlist, port)
		} else {
			proxy.Proxy(client, net.JoinHostPort(host, strconv.Itoa(port)))
		}
	} else {
		if pDSTAddr != nil {
			switch Proxy.Type {
			case proxy.HTTP:
				proxy.HTTPProxyAddr(Proxy.AddrList, client, pDSTAddr)
			case proxy.Socks5:
				proxy.SocksProxyAddr(Proxy.AddrList, client, pDSTAddr)
			case proxy.BIND:
				proxy.BindProxyAddr(Proxy.AddrList, Proxy.Option, client,
					pDSTAddr, int(Proxy.MSS), false)
			case proxy.BINDTFO:
				proxy.BindProxyAddr(Proxy.AddrList, Proxy.Option, client,
					pDSTAddr, int(Proxy.MSS), true)
			}
		} else {
			switch Proxy.Type {
			case proxy.Socks5:
				proxy.SocksProxyHost(Proxy.AddrList, client, host, port)
			case proxy.HTTP:
				proxy.HTTPProxyHost(Proxy.AddrList, client, host, port)
			case proxy.BIND:
				proxy.BindProxyHost(Proxy.AddrList, Proxy.Option,
					client, host, port,
					int(Proxy.MSS), false)
			case proxy.BINDTFO:
				proxy.BindProxyHost(Proxy.AddrList, Proxy.Option,
					client, host, port,
					int(Proxy.MSS), true)
			case proxy.MOVE:
				proxy.MoveProxyHost(Proxy.AddrList, client,
					Proxy.Option, port, int(Proxy.MSS), false)
			case proxy.MOVETFO:
				proxy.MoveProxyHost(Proxy.AddrList, client,
					Proxy.Option, port, int(Proxy.MSS), true)
			case proxy.TTL:
				proxy.TTLProxyHost(Proxy.AddrList, Proxy.Option,
					client, host, port, int(Proxy.MSS))
			case proxy.TTLS:
				proxy.TTLSProxyHost(Proxy.AddrList, Proxy.Option,
					client, host, port, int(Proxy.MSS))
			case proxy.TFO:
				proxy.ForceTFOProxyHost(Proxy.AddrList, Proxy.Option,
					client, host, port, int(Proxy.MSS))
			}
		}
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	Args := os.Args
	fmt.Println(Args)

	var randport bool = false

	argcount := len(Args)
	if argcount > 1 {
		//Config
		CacheMap = make(map[string]DNSCache)
		ProxyMap = make(map[uint64]*proxy.ProxyInfo)
		ProxyClients = make(map[string]bool)
		DNSAddress, _ = net.ResolveUDPAddr("udp", ":53")

		for _, arg := range Args[:] {
			if arg == "-4" {
				DNSMode = 4
			} else if arg == "-6" {
				DNSMode = 6
			} else if arg == "-r" {
				randport = true
			} else if arg == "--log" {
				LogEnable = true
			} else {
				err := handleLoadConfig(arg)
				if err != nil {
					log.Println(err)
					return
				}
			}
		}
	} else {
		fmt.Println("-4 IPv4\r\n-6 IPv6\r\n-r Random DNS Port\r\n")
		return
	}

	//DNS
	if DNSAddress.Port > 0 {
		udpconn, err := net.ListenUDP("udp", DNSAddress)
		if err != nil {
			log.Panic(err)
			return
		}
		defer udpconn.Close()
		go handleDNSServer(udpconn, randport)
	}

	//Proxy
	for {
		l, err := net.ListenTCP("tcp", &ProxyAddress)
		defer l.Close()
		if err == nil {
			for {
				client, err := l.AcceptTCP()
				if err != nil {
					log.Println(err)
					l.Close()
					break
				}

				go handleProxy(client)
			}

		} else {
			//log.Panic(err)
			log.Println(err)
		}

		time.Sleep(time.Duration(3) * time.Second)
	}

}
