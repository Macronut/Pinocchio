package service

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"../dns"
	"../proxy"
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
var ProxyClients map[string]bool
var DefaultFakeTTL uint8 = 0
var DefaultFakeAnswer dns.Answers = dns.NoAnswer
var DefaultProxy *proxy.ProxyInfo = nil
var Nose []DNSTruth = []DNSTruth{DNSTruth{"pinocchio", nil}}
var DNSMode int = 0
var MinCacheTTL int = 0
var RandPort bool = false
var DomainNeeded bool = false
var BogusPriv bool = false
var LogEnable bool = false
var DNSEnable bool = false
var WANList []string

var indexWaiting uint16 = 0
var DNSReadLock sync.RWMutex

func handleDNSForward(server *net.UDPConn, client *net.UDPConn, clientsList *[]*ClientInfo, idMask uint16) {
	defer server.Close()

	data := make([]byte, 2048)

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

		DNSReadLock.Lock()
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
		DNSReadLock.Unlock()

		clientInfo := (*clientsList)[index]
		if clientInfo != nil {
			binary.BigEndian.PutUint16(data[:2], clientInfo.ID)
			var question dns.Question

			if BogusPriv {
				var off int
				question, off, _ = dns.UnpackQuestion(data[offset:n])
				offset += off

				addrList := dns.UnPackAnswers(data[offset:n], int(header.ANCount))
				priv := false
				if question.QType == dns.TypeA {
					for _, addr := range addrList {
						nIP := binary.BigEndian.Uint32(addr.IP[:4])
						if (nIP & 0xFF000000) == 0x0A000000 { //10.0.0.0
							priv = true
						} else if (nIP & 0xFFE00000) == 0xAC100000 { //172.16.0.0
							priv = true
						} else if (nIP & 0xFFFF0000) == 0xC0A80000 { //192.168.0.0
							priv = true
						} else if (nIP & 0xFFC00000) == 0x64400000 { //100.64.0.0
							priv = true
						}
					}
				} else if question.QType == dns.TypeAAAA {
					for _, addr := range addrList {
						if (addr.IP[0] & 0xF0) != 0x20 {
							priv = true
						}
					}
				}

				if priv {
					continue
				}

				_, err = client.WriteToUDP(data[:n], clientInfo.Client)
			} else {
				var off int
				_, err = client.WriteToUDP(data[:n], clientInfo.Client)

				question, off, _ = dns.UnpackQuestion(data[offset:n])
				offset += off
			}

			if (question.QType != dns.TypeA) && (question.QType != dns.TypeAAAA) {
				(*clientsList)[header.ID] = nil
				continue
			}

			qname := question.QName
			adata := make([]byte, n-offset)
			copy(adata, data[offset:n])
			answers := dns.Answers{time.Now().Unix() + int64(MinCacheTTL), header.ANCount, header.NSCount, header.ARCount, adata}
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
		}
	}
}

func handleUDPForward(id uint16, curCache *DNSCache, server *net.UDPConn, client *net.UDPConn, clientAddr *net.UDPAddr) {
	defer server.Close()

	data := make([]byte, 2048)
	server.SetReadDeadline(time.Now().Add(time.Second * 5))
	for {
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

			var question dns.Question
			if BogusPriv {
				var off int
				question, off, _ = dns.UnpackQuestion(data[offset:n])
				if (question.QType != dns.TypeA) && (question.QType != dns.TypeAAAA) {
					continue
				}
				offset += off

				addrList := dns.UnPackAnswers(data[offset:n], int(header.ANCount))
				if question.QType == dns.TypeA {
					for _, addr := range addrList {
						nIP := binary.BigEndian.Uint32(addr.IP[:4])
						if (nIP & 0xFF000000) == 0x0A000000 { //10.0.0.0
							return
						} else if (nIP & 0xFFE00000) == 0xAC100000 { //172.16.0.0
							return
						} else if (nIP & 0xFFFF0000) == 0xC0A80000 { //192.168.0.0
							return
						} else if (nIP & 0xFFC00000) == 0x64400000 { //100.64.0.0
							return
						}
					}
				} else if question.QType == dns.TypeAAAA {
					for _, addr := range addrList {
						if (addr.IP[0] & 0xF0) != 0x20 {
							return
						}
					}
				}
				_, err = client.WriteToUDP(data[:n], clientAddr)
			} else {
				_, err = client.WriteToUDP(data[:n], clientAddr)
				var off int
				question, off, _ = dns.UnpackQuestion(data[offset:n])
				if (question.QType != dns.TypeA) && (question.QType != dns.TypeAAAA) {
					continue
				}
				offset += off
			}

			qname := question.QName
			adata := make([]byte, n-offset)
			copy(adata, data[offset:n])
			answers := dns.Answers{time.Now().Unix() + int64(MinCacheTTL), header.ANCount, header.NSCount, header.ARCount, adata}

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
			return
		}
	}
}

func handleTCPForward(header dns.Header, question dns.Question, curCache *DNSCache,
	client *net.UDPConn, clientAddr *net.UDPAddr) {

	var request []byte
	var cache DNSCache = *curCache
	proxy46 := cache.Proxy != nil && cache.AAAA == nil && question.QType == dns.TypeA
	if proxy46 {
		question.QType = dns.TypeAAAA
		request = dns.PackRequest(header, question)
	}
	request = dns.PackRequest(header, question)

	var err error
	var response []byte
	serverAddrCount := len(cache.Server.AddrList)
	if serverAddrCount > 0 {
		serverAddr := cache.Server.AddrList[rand.Intn(serverAddrCount)]
		response, err = dns.TCPLookup(request, serverAddr.String())
	} else {
		response, err = dns.TCPLookup(request, cache.Server.Option)
	}
	if err != nil {
		log.Println(err)
		return
	}

	header, offset := dns.UnpackHeader(response)
	if offset > len(response) {
		log.Println(question.QName, response)
		return
	}
	question, off, _ := dns.UnpackQuestion(response[offset:])
	offset += off

	client.WriteToUDP(response, clientAddr)
	answers := dns.Answers{time.Now().Unix() + int64(MinCacheTTL), header.ANCount, header.NSCount, header.ARCount, response[offset:]}
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
}

func handleMystifyTCPForward(header dns.Header, question dns.Question, curCache *DNSCache,
	client *net.UDPConn, clientAddr *net.UDPAddr) {

	var request []byte
	var cache DNSCache = *curCache
	proxy46 := cache.Proxy != nil && cache.AAAA == nil && question.QType == dns.TypeA
	if proxy46 {
		question.QType = dns.TypeAAAA
		request = dns.PackRequest(header, question)
	}
	request = dns.PackRequest(header, question)

	var err error
	var response []byte
	serverAddrCount := len(cache.Server.AddrList)
	if serverAddrCount > 0 {
		serverAddr := cache.Server.AddrList[rand.Intn(serverAddrCount)]
		response, err = proxy.MystifyTCPLookup(request, serverAddr.String(), int(DefaultFakeTTL))
	} else {
		response, err = proxy.MystifyTCPLookup(request, cache.Server.Option, int(DefaultFakeTTL))
	}
	if err != nil {
		log.Println(err)
		return
	}

	header, offset := dns.UnpackHeader(response)
	if offset > len(response) {
		log.Println(question.QName, response)
		return
	}
	question, off, _ := dns.UnpackQuestion(response[offset:])
	offset += off

	client.WriteToUDP(response, clientAddr)
	answers := dns.Answers{time.Now().Unix() + int64(MinCacheTTL), header.ANCount, header.NSCount, header.ARCount, response[offset:]}
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
}

func handleHTTPSForward(header dns.Header, question dns.Question, curCache *DNSCache,
	client *net.UDPConn, clientAddr *net.UDPAddr) {
	IPList, err := dns.HTTPSLookup(question.QName, question.QType, curCache.Server.Option)

	if err != nil {
		log.Println(err)
		return
	}

	serverAddrCount := len(curCache.Server.AddrList)
	if serverAddrCount > 0 {
		serverAddr := curCache.Server.AddrList[0]
		for i, addr := range IPList {
			ip := addr.IP.To16()
			copy(ip[:12], serverAddr.IP[:12])
			IPList[i].IP = ip
		}
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
	question, off, _ := dns.UnpackQuestion(response[offset:])
	offset += off

	var cache DNSCache = *curCache
	client.WriteToUDP(response, clientAddr)
	answers := dns.Answers{time.Now().Unix() + int64(MinCacheTTL), header.ANCount, header.NSCount, header.ARCount, response[offset:]}
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
			return cache
		}
		offset++
	}

	return DefaultServer
}

func AddLie(question dns.Question, cache DNSCache) *dns.Answers {
	var answers *dns.Answers = nil
	if DNSMode == 4 {
		if question.QType != dns.TypeA {
			return &dns.NoAnswer
		}
	} else {
		if question.QType != dns.TypeAAAA {
			return &dns.NoAnswer
		}
	}

	newID := len(Nose)
	lie := dns.BuildLie(newID, question.QType)
	answers = &lie
	cache.AAAA = &dns.NoAnswer
	cache.A = answers
	CacheLock.Lock()
	Nose = append(Nose, DNSTruth{question.QName, cache.Proxy})
	if LogEnable {
		fmt.Println("DNSLIE", question.QName, proxy.TypeList[cache.Proxy.Type])
	}

	CacheMap[question.QName] = cache
	CacheLock.Unlock()
	return answers
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
	if cache.Proxy == nil {
		if qtype == dns.TypeA {
			answers = cache.A
		} else if qtype == dns.TypeAAAA {
			answers = cache.AAAA
		}
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
						question, off, _ := dns.UnpackQuestion(data[offset:n])
						offset += off

						if cache.Proxy == nil {
							qname := string(question.QName)
							adata := make([]byte, n-offset)
							copy(adata, data[offset:n])
							answers := dns.Answers{
								time.Now().Unix() + int64(MinCacheTTL),
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
				var err error
				var response []byte
				serverAddrCount := len((*cache.Server).AddrList)
				if serverAddrCount > 0 {
					serverAddr := (*cache.Server).AddrList[rand.Intn(serverAddrCount)]
					response, err = dns.TCPLookup(request, serverAddr.String())
				} else {
					response, err = dns.TCPLookup(request, curCache.Server.Option)
				}
				if err != nil {
					if LogEnable {
						log.Println(err)
					}
					return nil
				}
				header, offset := dns.UnpackHeader(response)
				question, off, _ := dns.UnpackQuestion(response[offset:])
				offset += off

				if cache.Proxy == nil {
					qname := string(question.QName)
					adata := make([]byte, len(response)-offset)
					copy(adata, response[offset:])
					answers := dns.Answers{time.Now().Unix() + int64(MinCacheTTL),
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

				IPList := dns.UnPackAnswers(response[offset:], int(header.ANCount))
				return IPList
			case dns.MYTCP:
				var err error
				var response []byte
				serverAddrCount := len((*cache.Server).AddrList)
				if serverAddrCount > 0 {
					serverAddr := (*cache.Server).AddrList[rand.Intn(serverAddrCount)]
					response, err = proxy.MystifyTCPLookup(request, serverAddr.String(), int(DefaultFakeTTL))
				} else {
					response, err = proxy.MystifyTCPLookup(request, curCache.Server.Option, int(DefaultFakeTTL))
				}
				if err != nil {
					if LogEnable {
						log.Println(err)
					}
					return nil
				}
				header, offset := dns.UnpackHeader(response)
				question, off, _ := dns.UnpackQuestion(response[offset:])
				offset += off

				if cache.Proxy == nil {
					qname := string(question.QName)
					adata := make([]byte, len(response)-offset)
					copy(adata, response[offset:])
					answers := dns.Answers{time.Now().Unix() + int64(MinCacheTTL),
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

				IPList := dns.UnPackAnswers(response[offset:], int(header.ANCount))
				return IPList
			case dns.HTTPS:
				IPList, _ := dns.HTTPSLookup(question.QName, question.QType, cache.Server.Option)
				return IPList
			case dns.DOH:
				response, err := dns.DoHLookup(request, cache.Server.Option)
				if err != nil {
					return nil
				}
				header, offset := dns.UnpackHeader(response)
				question, off, _ := dns.UnpackQuestion(response[offset:])
				offset += off

				if cache.Proxy == nil {
					qname := string(question.QName)
					adata := make([]byte, len(response)-offset)
					copy(adata, response[offset:])
					answers := dns.Answers{time.Now().Unix() + int64(MinCacheTTL),
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

				IPList := dns.UnPackAnswers(response[offset:], int(header.ANCount))
				return IPList
			}
		}
	} else {
		return dns.UnPackAnswers(answers.Answers, int(answers.ANCount))
	}

	return nil
}

var DNSIndex uint16 = 0
var DNSLock sync.RWMutex
var IDMask uint16 = uint16(time.Now().UnixNano() & 0xFFFF)

func handleDNSServer(client *net.UDPConn, randport bool) {
	data := make([]byte, 512)

	var server *net.UDPConn = nil
	var clientsList []*ClientInfo

	if randport == false {
		addr, err := net.ResolveUDPAddr("udp", ":0")
		server, err = net.ListenUDP("udp", addr)

		if err != nil {
			log.Println(err)
			return
		}
		clientsList = make([]*ClientInfo, 65536)
		go handleDNSForward(server, client, &clientsList, IDMask)
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
		question, off, isdomain := dns.UnpackQuestion(data[off:n])

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

		if DomainNeeded {
			if isdomain {
				if strings.HasSuffix(question.QName, ".arpa") {
					continue
				}
			} else {
				continue
			}
		}

		if cache.Proxy != nil {
			var response []byte
			if DefaultFakeAnswer.Answers == nil {
				answers = AddLie(question, cache)
				response = dns.QuickResponse(data[:n], *answers)
			} else {
				response = dns.QuickResponse(data[:n], DefaultFakeAnswer)
			}
			client.WriteToUDP(response, clientAddr)
		} else if cache.Server != nil {
			if LogEnable {
				fmt.Println("DNS", clientAddr.IP, question.QName, question.QType, dns.TypeList[(*cache.Server).Type], time.Since(Now))
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
					clientsList[DNSIndex] = &ClientInfo{id, time.Now().Unix(), clientAddr, &cache}
					binary.BigEndian.PutUint16(data[:], DNSIndex^IDMask)
					for _, serverAddr := range (*cache.Server).AddrList {
						_, err = server.WriteToUDP(data[:n], &serverAddr)
						if err != nil {
							log.Println(err)
							continue
						}
					}
					DNSLock.Lock()
					DNSIndex++
					DNSLock.Unlock()
				}
			case dns.TCP:
				go handleTCPForward(header, question, &cache, client, clientAddr)
			case dns.MYTCP:
				go handleMystifyTCPForward(header, question, &cache, client, clientAddr)
			case dns.HTTPS:
				go handleHTTPSForward(header, question, &cache, client, clientAddr)
			case dns.DOH:
				go handleDOHForward(header, question, &cache, client, clientAddr)
			}
		}
	}
}

func handleDNSoverTCP(client *net.TCPConn) {
	defer client.Close()
	data := make([]byte, 512)

	n, err := client.Read(data)
	if err != nil {
		log.Println(err)
		return
	}

	Now := time.Now()
	if n < 12 {
		return
	}
	length := int(binary.BigEndian.Uint16(data[:2]))
	if n-length != 2 {
		log.Println("Invalid DNS Length")
		return
	}
	header, off := dns.UnpackHeader(data[2:n])
	off += 2
	if header.QDCount == 0 {
		return
	}
	question, off, isdomain := dns.UnpackQuestion(data[off:n])

	if off == 0 {
		log.Println(question.QName, "ERROR")
		return
	}

	cache := CacheLookup(question.QName)

	var answers *dns.Answers = nil
	if question.QType == dns.TypeA {
		answers = cache.A
	} else if question.QType == dns.TypeAAAA {
		answers = cache.AAAA
	}

	if answers != nil {
		response := dns.QuickResponse(data[2:n], *answers)
		n = len(response)
		binary.BigEndian.PutUint16(data[:2], uint16(n))
		copy(data[2:], response)
		n += 2
		client.Write(data[:n])
	}

	if DomainNeeded {
		if isdomain {
			if strings.HasSuffix(question.QName, ".arpa") {
				return
			}
		} else {
			return
		}
	}

	if cache.Proxy != nil {
		answers = AddLie(question, cache)
		response := dns.QuickResponse(data[2:n], *answers)
		n = len(response)
		binary.BigEndian.PutUint16(data[:2], uint16(n))
		copy(data[2:], response)
		n += 2
		client.Write(data[:n])
	} else if cache.Server != nil {
		if LogEnable {
			fmt.Println("DNS", question.QName, question.QType, dns.TypeList[(*cache.Server).Type], time.Since(Now))
		}

		switch (*cache.Server).Type {
		case dns.UDP:
			fallthrough
		case dns.TCP:
			fallthrough
		case dns.MYTCP:
			fallthrough
		case dns.HTTPS:
			fallthrough
		case dns.DOH:
			fallthrough
		default:
			addrlist := NSLookup(question.QName, question.QType, &cache)
			answers := dns.PackAnswersTTL(addrlist)
			response := dns.QuickResponse(data[2:n], answers)
			n = len(response)
			binary.BigEndian.PutUint16(data[:2], uint16(n))
			copy(data[2:], response)
			n += 2
			client.Write(data[:n])
		}
	}
}

func handleProxyHost(client *net.TCPConn, Proxy *proxy.ProxyInfo, host string, port int, headData []byte) {
	err := client.SetReadDeadline(time.Now().Add(proxy.CONN_TTL))
	if err != nil {
		log.Println(err)
	}
	defer client.Close()

	if Proxy == nil {
		if len(headData) > 0 {
			proxy.ProxyTFO(client, net.JoinHostPort(host, strconv.Itoa(port)), headData)
		} else {
			if DNSEnable {
				proxy.Proxy(client, net.JoinHostPort(host, strconv.Itoa(port)))
			} else {
				addrlist := make([]proxy.AddrInfo, 0)
				for _, addr := range NSLookup(host, 1, nil) {
					addrlist = append(addrlist, proxy.AddrInfo{addr, ""})
				}
				proxy.ProxyAddress(client, addrlist, port)
			}
		}
	} else {
		if len(Proxy.AddrList) == 0 {
			if Proxy.Type == proxy.NULL {
				cache := CacheLookup(net.JoinHostPort(host, strconv.Itoa(port)))
				Proxy = cache.Proxy
			} else {
				cache := CacheLookup(host)
				addrlist := make([]proxy.AddrInfo, 0)
				if cache.AAAA == nil {
					for _, addr := range NSLookup(host, 28, &cache) {
						addrlist = append(addrlist, proxy.AddrInfo{addr, ""})
					}
				} else {
					for _, addr := range NSLookup(host, 1, &cache) {
						addrlist = append(addrlist, proxy.AddrInfo{addr, ""})
					}
				}
				if addrlist == nil {
					return
				}
				proxy := *Proxy
				proxy.AddrList = addrlist
				Proxy = &proxy
				cache.Proxy = &proxy
				CacheLock.Lock()
				CacheMap[host] = cache
				CacheLock.Unlock()

				if LogEnable {
					log.Println(host, port, Proxy)
				}
			}
		}
		switch Proxy.Type {
		case proxy.SOCKS:
			proxy.SocksProxyHost(Proxy.AddrList, Proxy.Option, client, host, port)
		case proxy.HTTP:
			proxy.HTTPProxyHost(Proxy.AddrList, client, host, port)
		case proxy.BIND:
			proxy.BindProxyHost(Proxy.AddrList, Proxy.Option,
				client, host, port,
				int(Proxy.MSS), headData)
		case proxy.MOVE:
			proxy.MoveProxyHost(Proxy.AddrList, client,
				Proxy.Option, port, int(Proxy.MSS), headData)
		case proxy.MYSTIFY:
			proxy.MystifyProxy(Proxy.AddrList, Proxy.Option,
				client, host, port, int(Proxy.TTL), int(Proxy.MSS), headData)
		case proxy.MYSTIFY6:
			proxy.MystifyProxy6(Proxy.AddrList, Proxy.Option,
				client, host, port, int(Proxy.TTL), int(Proxy.MSS), false, headData)
		case proxy.MYTCPMD5:
			proxy.MystifyProxy6(Proxy.AddrList, Proxy.Option,
				client, host, port, int(Proxy.TTL), int(Proxy.MSS), true, headData)
		case proxy.MYHTTP:
			proxy.MystifyHTTP(Proxy.AddrList, Proxy.Option,
				client, host, port, int(Proxy.TTL), int(Proxy.MSS))
		case proxy.MYHTTP6:
			proxy.MystifyProxyHTTP6(Proxy.AddrList, Proxy.Option,
				client, host, port, int(Proxy.TTL), int(Proxy.MSS), false)
		case proxy.MYPROXY:
			proxy.MystifyHTTPProxy(Proxy.AddrList, Proxy.Option,
				client, host, port, int(Proxy.TTL), int(Proxy.MSS), headData)
		case proxy.MYSOCKS:
			proxy.MystifySocksProxy(Proxy.AddrList, Proxy.Option,
				client, host, port, int(Proxy.TTL), int(Proxy.MSS), headData)
		case proxy.MYSOCKS4:
			proxy.MystifySocks4Proxy(Proxy.AddrList, Proxy.Option,
				client, host, port, int(Proxy.TTL), int(Proxy.MSS), headData)
		case proxy.MYSOCKS4A:
			proxy.MystifySocks4aProxy(Proxy.AddrList, Proxy.Option,
				client, host, port, int(Proxy.TTL), int(Proxy.MSS), headData)
		case proxy.TFO:
			proxy.TFOProxyHost(Proxy.AddrList, Proxy.Option,
				client, host, port, int(Proxy.MSS), headData)
		case proxy.STRIP:
			proxy.StripHost(Proxy.AddrList, Proxy.Option,
				client, host, port, headData)
		case proxy.WEB:
			proxy.WebProxyHost(client, host, Proxy.Option, headData)
		default:
			log.Println("No Type:", Proxy.Type)
		}
	}
}

func handleProxyAddr(client *net.TCPConn, Proxy *proxy.ProxyInfo, pDSTAddr *net.TCPAddr) {
	err := client.SetReadDeadline(time.Now().Add(proxy.CONN_TTL))
	if err != nil {
		log.Println(err)
	}
	defer client.Close()

	if Proxy == nil {
		proxy.Proxy(client, pDSTAddr.String())
	} else {
		switch Proxy.Type {
		case proxy.SOCKS:
			proxy.SocksProxyAddr(Proxy.AddrList, Proxy.Option, client, pDSTAddr)
		case proxy.HTTP:
			proxy.HTTPProxyAddr(Proxy.AddrList, client, pDSTAddr)
		case proxy.BIND:
			proxy.BindProxyAddr(Proxy.AddrList, Proxy.Option, client,
				pDSTAddr, int(Proxy.MSS), false)
		case proxy.MYPROXY:
			ip4 := pDSTAddr.IP.To4()
			if ip4 != nil {
				host := ip4.String()
				port := pDSTAddr.Port
				proxy.MystifyHTTPProxy(Proxy.AddrList, Proxy.Option,
					client, host, port, int(Proxy.TTL), int(Proxy.MSS), nil)
			}
		case proxy.MYSOCKS:
			proxy.MystifySocksProxyAddr(Proxy.AddrList, Proxy.Option,
				client, pDSTAddr, int(Proxy.TTL), int(Proxy.MSS), nil)
		case proxy.MYSOCKS4:
			proxy.MystifySocks4ProxyAddr(Proxy.AddrList, Proxy.Option,
				client, pDSTAddr, int(Proxy.TTL), int(Proxy.MSS), nil)
		case proxy.MYSOCKS4A:
			proxy.MystifySocks4ProxyAddr(Proxy.AddrList, Proxy.Option,
				client, pDSTAddr, int(Proxy.TTL), int(Proxy.MSS), nil)
		default:
			log.Println("No Type:", Proxy.Type)
		}
	}
}

func handleTransparent(client *net.TCPConn) {
	defer client.Close()

	pDSTAddr, err := proxy.GetOriginalDST(client)
	if err != nil {
		log.Println(err)
		return
	}
	if pDSTAddr == nil {
		return
	}

	var headData []byte
	IP := []byte(pDSTAddr.IP)
	Type := binary.BigEndian.Uint16(IP[:2])
	switch Type {
	case 0x2000:
		index := int(binary.BigEndian.Uint32(IP[12:16]))
		if index >= len(Nose) {
			return
		}
		truth := Nose[index]
		handleProxyHost(client, truth.Proxy, truth.Host, pDSTAddr.Port, headData)
	case 0x0700:
		index := int(binary.BigEndian.Uint16(IP[2:4]))
		if index >= len(Nose) {
			return
		}
		truth := Nose[index]
		handleProxyHost(client, truth.Proxy, truth.Host, pDSTAddr.Port, headData)
	case 0x0701:
		handleReverse(client, pDSTAddr.Port)
		return
	default:
		var index uint64
		if len(IP) == 4 {
			index = uint64(binary.BigEndian.Uint32(IP[:4]))
		} else {
			index = binary.BigEndian.Uint64(IP[:8])
		}
		Proxy, ok := ProxyMap[index]
		if ok {
			handleProxyAddr(client, Proxy, pDSTAddr)
		} else {
			if LogEnable {
				log.Println(client.RemoteAddr(), pDSTAddr, ":Unknow IP")
			}
			return
		}
	}
}

func handleSocks(client *net.TCPConn) {
	defer client.Close()

	var b [1460]byte
	n, err := client.Read(b[:])
	if err != nil {
		return
	}

	if b[0] == 0x05 {
		client.Write([]byte{0x05, 0x00})
		n, err = client.Read(b[:])
		if err != nil {
			return
		}
		switch b[1] {
		case 0x01:
			{
				switch b[3] {
				case 0x01:
					index := uint64(binary.BigEndian.Uint32(b[4:8]))
					port := int(b[n-2])<<8 | int(b[n-1])
					pDSTAddr := &net.TCPAddr{b[4:8], port, ""}
					Proxy, ok := ProxyMap[index]
					if !ok {
						Proxy, ok = ProxyMap[index&0xFFFFFF00]
					}
					if !ok {
						Proxy, ok = ProxyMap[index&0xFFFF0000]
					}
					if !ok {
						Proxy = DefaultProxy
					}
					if LogEnable {
						fmt.Println("SOCKS-IPv4", client.RemoteAddr(), pDSTAddr)
					}
					client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
					handleProxyAddr(client, Proxy, pDSTAddr)
				case 0x03:
					host := string(b[5 : n-2])
					port := int(b[n-2])<<8 | int(b[n-1])
					cache := CacheLookup(host)
					Proxy := cache.Proxy
					if LogEnable {
						fmt.Println("SOCKS", client.RemoteAddr(), host, port)
					}
					client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
					handleProxyHost(client, Proxy, host, port, nil)
				case 0x04:
					index := binary.BigEndian.Uint64(b[4:12])
					port := int(b[n-2])<<8 | int(b[n-1])
					pDSTAddr := &net.TCPAddr{b[4:20], port, ""}
					var ok bool
					Proxy, ok := ProxyMap[index]
					if !ok {
						Proxy, ok = ProxyMap[index&0xFFFFFFFFFFFF0000]
					}
					if !ok {
						Proxy, ok = ProxyMap[index&0xFFFFFFFF00000000]
					}
					if !ok {
						log.Println(pDSTAddr, ":Unknow IP")
						return
					}
					if LogEnable {
						fmt.Println("SOCKS-IPv6", client.RemoteAddr(), pDSTAddr)
					}
					client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
					handleProxyAddr(client, Proxy, pDSTAddr)
				}
			}
		case 0x02:
			{
				fmt.Println("BIND not Support")
			}
		case 0x03:
			{
				fmt.Println("UDP ASSOCIATE not Support")
			}
		}
	}
}

func handleGlobalSocks(client *net.TCPConn, Proxy *proxy.ProxyInfo) {
	defer client.Close()

	var b [1460]byte
	n, err := client.Read(b[:])
	if err != nil {
		return
	}

	if b[0] == 0x05 {
		client.Write([]byte{0x05, 0x00})
		n, err = client.Read(b[:])
		if err != nil {
			return
		}
		switch b[3] {
		case 0x01:
			port := int(b[n-2])<<8 | int(b[n-1])
			pDSTAddr := &net.TCPAddr{b[4:8], port, ""}
			if LogEnable {
				fmt.Println("SOCKS-IPv4", client.RemoteAddr(), pDSTAddr)
			}
			client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			handleProxyAddr(client, Proxy, pDSTAddr)
		case 0x03:
			host := string(b[5 : n-2])
			port := int(b[n-2])<<8 | int(b[n-1])
			if LogEnable {
				fmt.Println("SOCKS", client.RemoteAddr(), host, port)
			}
			client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			handleProxyHost(client, Proxy, host, port, nil)
		case 0x04:
			port := int(b[n-2])<<8 | int(b[n-1])
			pDSTAddr := &net.TCPAddr{b[4:20], port, ""}
			if LogEnable {
				fmt.Println("SOCKS-IPv6", client.RemoteAddr(), pDSTAddr)
			}
			client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			handleProxyAddr(client, Proxy, pDSTAddr)
		}
	}
}

func handleReverse(client *net.TCPConn, port int) {
	defer client.Close()

	var host string
	var Proxy *proxy.ProxyInfo = nil

	var headData []byte

	var b [1460]byte
	n, err := client.Read(b[:])
	if n <= 0 {
		return
	}

	if b[0] == 0x16 {
		host = proxy.GetSNI(b[:n])
		if len(host) > 0 {
			cache := CacheLookup(host)
			Proxy = cache.Proxy
			if LogEnable {
				fmt.Println("SNI", host, port)
				if strings.HasSuffix(host, ".info") {
					sni := base64.URLEncoding.EncodeToString(b[:n])
					if err != nil {
						log.Fatalln(err)
					}
					fmt.Println("SNIBase64", n, sni)
				}
			}
			headData = make([]byte, n)
			copy(headData[:], b[:n])
		} else {
			return
		}
	} else {
		host = proxy.GetHost(b[:n])
		if len(host) > 0 {
			if len(ProxyClients) == 0 {
				if strings.Index(host, ":") == -1 {
					if (host + ":80") == client.LocalAddr().String() {
						//client.Write([]byte("HTTP/1.1 301 Moved Permanently\r\nLocation: http://127.0.0.1\r\n\r\n"))
						client.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
						log.Println(client.RemoteAddr(), host, "Unauthorized Access")
						if LogEnable {
							fmt.Println(string(b[:n]))
						}
						return
					}
				}
			}

			cache := CacheLookup(host)
			Proxy = cache.Proxy
			if LogEnable {
				fmt.Println("HTTP", host, port)
			}
			headData = make([]byte, n)
			copy(headData[:], b[:n])
		} else {
			return
		}
	}

	handleProxyHost(client, Proxy, host, port, headData)
}

func PinocchioDNS(Address net.UDPAddr) error {
	udpconn, err := net.ListenUDP("udp", &Address)
	if err != nil {
		return err
	}
	defer udpconn.Close()
	DNSEnable = true
	handleDNSServer(udpconn, RandPort)
	return nil
}

func PinocchioDNSoverTCP(ProxyAddress net.TCPAddr) error {
	l, err := net.ListenTCP("tcp", &ProxyAddress)
	if err != nil {
		return err
	}
	defer l.Close()

	if LogEnable {
		fmt.Println("DNSoverTCP:", ProxyAddress.String())
	}

	for {
		client, err := l.AcceptTCP()
		if err != nil {
			log.Println(err)
			time.Sleep(time.Second * 2)
			continue
		}

		go handleDNSoverTCP(client)
	}
	return nil
}

func PinocchioProxy(ProxyAddress net.TCPAddr) error {
	proxy.LogEnable = LogEnable
	l, err := net.ListenTCP("tcp", &ProxyAddress)
	if err != nil {
		return err
	}
	defer l.Close()
	for {
		client, err := l.AcceptTCP()
		if err != nil {
			log.Println(err)
			return err
		}

		if len(ProxyClients) > 0 {
			RemoteAddr := client.RemoteAddr()
			RemoteTCPAddr, _ := net.ResolveTCPAddr(RemoteAddr.Network(), RemoteAddr.String())
			strIP := RemoteTCPAddr.IP.String()
			_, ok := ProxyClients[strIP]
			if !ok {
				if LogEnable {
					fmt.Println(strIP, "Forbidden")
				}
				client.Close()
				continue
			}
		}

		go handleTransparent(client)
	}
	return nil
}

var QUICLock sync.RWMutex
var QUICMap map[string]*net.UDPConn

func PinocchioQUICProxy(ProxyAddress net.UDPAddr) error {
	client, err := net.ListenUDP("udp", &ProxyAddress)
	if err != nil {
		log.Println(err)
		return err
	}
	defer client.Close()

	QUICMap = make(map[string]*net.UDPConn)
	data := make([]byte, 1500)

	for {
		n, clientAddr, err := client.ReadFromUDP(data)
		if err != nil {
			log.Println(err)
			time.Sleep(time.Second * 2)
			continue
		}

		QUICLock.Lock()
		udpConn, ok := QUICMap[clientAddr.String()]
		QUICLock.Unlock()

		if ok {
			udpConn.Write(data[:n])
		} else {
			var host string
			if data[0] == 13 {
				host = proxy.GetQUICSNI(data[:n])
			} else {
				continue
			}

			if len(host) > 0 {
				cache := CacheLookup(host)
				Proxy := cache.Proxy

				if Proxy != nil && Proxy.Type == proxy.MYSTIFY {
					addrCount := len(Proxy.AddrList)
					dstAddr := net.UDPAddr(Proxy.AddrList[rand.Intn(addrCount)].Address)
					dstAddr.Port = 443

					if LogEnable {
						fmt.Println("[QUIC]", host, dstAddr)
					}
					udpConn, err = net.DialUDP("udp", nil, &dstAddr)
					if err != nil {
						log.Println(err)
						continue
					}

					QUICMap[clientAddr.String()] = udpConn
					_, err = udpConn.Write(data[:n])
					if err != nil {
						log.Println(err)
						continue
					}

					go func(clientAddr net.UDPAddr) {
						data := make([]byte, 1500)
						udpConn.SetReadDeadline(time.Now().Add(time.Minute * 2))
						for {
							n, err := udpConn.Read(data)
							if err != nil {
								QUICLock.Lock()
								delete(QUICMap, clientAddr.String())
								QUICLock.Unlock()
								udpConn.Close()
								return
							}
							udpConn.SetReadDeadline(time.Now().Add(time.Minute * 2))
							client.WriteToUDP(data[:n], &clientAddr)
						}
					}(*clientAddr)
				}
			}
		}
	}
}

func SocksProxy(ProxyAddress net.TCPAddr, Authentication string, Quote string) error {
	proxy.LogEnable = LogEnable
	l, err := net.ListenTCP("tcp", &ProxyAddress)
	if err != nil {
		return err
	}
	defer l.Close()

	if LogEnable {
		fmt.Println("SocksProxy:", ProxyAddress.String())
	}

	for {
		//l.SetDeadline(time.Now().Add(time.Second * 2))
		client, err := l.AcceptTCP()
		if err != nil {
			log.Println(err)
			time.Sleep(time.Second * 2)
			continue
		}

		if len(ProxyClients) > 0 {
			RemoteAddr := client.RemoteAddr()
			RemoteTCPAddr, _ := net.ResolveTCPAddr(RemoteAddr.Network(), RemoteAddr.String())
			strIP := RemoteTCPAddr.IP.String()
			_, ok := ProxyClients[strIP]
			if !ok {
				if LogEnable {
					fmt.Println(strIP, "Forbidden")
				}
				client.Close()
				continue
			}
		}

		if Quote == "" {
			go handleSocks(client)
		} else {
			cache := CacheLookup(Quote)
			Proxy := cache.Proxy
			go handleGlobalSocks(client, Proxy)
		}
	}
	return nil
}

func ReverseProxy(ProxyAddress net.TCPAddr) error {
	proxy.LogEnable = LogEnable
	go PinocchioQUICProxy(net.UDPAddr(ProxyAddress))

	l, err := net.ListenTCP("tcp", &ProxyAddress)
	if err != nil {
		log.Println(err)
		return err
	}
	defer l.Close()

	if LogEnable {
		fmt.Println("ReverseProxy:", ProxyAddress.String())
	}

	for {
		client, err := l.AcceptTCP()
		if err != nil {
			log.Println(err)
			time.Sleep(time.Second * 2)
			continue
		}

		if len(ProxyClients) > 0 {
			RemoteAddr := client.RemoteAddr()
			RemoteTCPAddr, _ := net.ResolveTCPAddr(RemoteAddr.Network(), RemoteAddr.String())
			strIP := RemoteTCPAddr.IP.String()
			_, ok := ProxyClients[strIP]
			if !ok {
				if LogEnable {
					fmt.Println(strIP, "Forbidden")
				}
				client.Close()
				continue
			}
		}

		go handleReverse(client, ProxyAddress.Port)
	}
	return nil
}
