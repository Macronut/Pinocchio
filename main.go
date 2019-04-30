package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"./dns"
	"./proxy"
	"./service"
)

var ProxyAddress *net.TCPAddr = nil
var DNSPort int = 0
var ListenAddress []*net.UDPAddr = nil

func handleLoadConfig(line string) error {
	if len(line) > 0 && !strings.HasPrefix(line, "#") {
		config := strings.SplitN(line, "/", 4)
		configType := strings.SplitN(config[0], "=", 2)
		if len(config) > 1 {
			if configType[0] == "quote" {
				IP := net.ParseIP(config[1])
				cache, ok := service.CacheMap[config[2]]
				if IP == nil {
					if ok {
						service.CacheMap[config[1]] = cache
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
					service.ProxyMap[index] = cache.Proxy
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

				var dnstype uint16 = dns.UDP

				var AnswerA *dns.Answers = nil
				var AnswerAAAA *dns.Answers = nil
				configDNSType := strings.SplitN(configType[1], ":", 2)
				if len(configDNSType) > 1 {
					if configDNSType[0] == "tcp" {
						dnstype = dns.TCP
					} else if configDNSType[0] == "mytcp" {
						dnstype = dns.MYTCP
					} else if configDNSType[0] == "https" {
						dnstype = dns.HTTPS
					} else if configDNSType[0] == "doh" {
						dnstype = dns.DOH
					} else {
						log.Println(line)
					}

					if configDNSType[1] == "A" {
						AnswerAAAA = &dns.NoAnswer
					} else if configDNSType[1] == "AAAA" {
						AnswerA = &dns.NoAnswer
					}
				} else {
					if configDNSType[0] == "A" {
						AnswerAAAA = &dns.NoAnswer
					} else if configDNSType[0] == "AAAA" {
						AnswerA = &dns.NoAnswer
					}
				}

				var option string

				if len(config) > 3 {
					option = config[3]
				} else {
					option = ""
				}

				dnsCache := service.DNSCache{
					AnswerA,
					AnswerAAAA,
					&service.ServerInfo{dnstype, addrlist, option},
					nil,
				}
				if config[1] == "" {
					service.DefaultServer = dnsCache
				} else {
					QName := config[1]
					service.CacheMap[QName] = dnsCache
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
					pProxy = &proxy.ProxyInfo{proxy.MOVE, 0, 0, nil, ""}
				}

				var AnswerA dns.Answers = dns.PackAnswers(AList)
				var AnswerAAAA dns.Answers = dns.PackAnswers(AAAAList)

				service.CacheMap[QName] = service.DNSCache{
					&AnswerA,
					&AnswerAAAA,
					nil,
					pProxy,
				}
			} else if configType[0] == "proxy" {
				var proxyType uint8
				netInfo := strings.Split(configType[1], ":")
				if netInfo[0] == "socks" {
					proxyType = proxy.SOCKS
				} else if netInfo[0] == "socks5" {
					proxyType = proxy.SOCKS
				} else if netInfo[0] == "http" {
					proxyType = proxy.HTTP
				} else if netInfo[0] == "6to4" {
					proxyType = proxy.IPv6to4
				} else if netInfo[0] == "4to6" {
					proxyType = proxy.IPv4to6
				} else if netInfo[0] == "bind" {
					proxyType = proxy.BIND
				} else if netInfo[0] == "move" {
					proxyType = proxy.MOVE
				} else if netInfo[0] == "myhttps" {
					proxyType = proxy.MYSTIFY
				} else if netInfo[0] == "myhttps6" {
					proxyType = proxy.MYSTIFY6
				} else if netInfo[0] == "mytcpmd5" {
					proxyType = proxy.MYTCPMD5
				} else if netInfo[0] == "myhttp" {
					proxyType = proxy.MYHTTP
				} else if netInfo[0] == "myhttp6" {
					proxyType = proxy.MYHTTP6
				} else if netInfo[0] == "tfo" {
					proxyType = proxy.TFO
				} else if netInfo[0] == "strip" {
					proxyType = proxy.STRIP
				} else {
					log.Println(string(line))
					return nil
				}

				ttl := service.DefaultFakeTTL
				var mss uint16 = 0
				if len(netInfo) > 1 {
					n, _ := strconv.Atoi(netInfo[1])
					mss = uint16(n)
					if len(netInfo) > 2 {
						n, _ := strconv.Atoi(netInfo[2])
						ttl = uint8(n)
					}
				}

				addrlist := make([]proxy.AddrInfo, 0)
				if config[2] != "" {
					for _, addrinfostr := range strings.Split(config[2], "|") {
						addrinfo := strings.SplitN(addrinfostr, "@", 2)
						addr := addrinfo[0]
						iface := ""
						if len(addrinfo) > 1 {
							iface = addrinfo[1]
						}

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
						addrlist = append(addrlist, proxy.AddrInfo{*serverAddr, iface})
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
					if config[1] == "*" {
						service.DefaultProxy = &proxy.ProxyInfo{proxyType, ttl, mss, addrlist, option}
						return nil
					}
					host_port := strings.SplitN(config[1], ":", 2)
					host := host_port[0]
					cache, ok := service.CacheMap[host]

					if len(host_port) > 1 {
						service.CacheMap[host] = service.DNSCache{
							nil, nil, nil,
							&proxy.ProxyInfo{0, 0, 0, nil, ""},
						}
					}

					if config[1] == "" {
						service.DefaultServer = service.DNSCache{nil, nil, nil,
							&proxy.ProxyInfo{proxyType, ttl, mss, addrlist, option},
						}
					} else {
						if ok {
							if cache.A == &dns.NoAnswer {
								cache.A = nil
							}
							service.CacheMap[config[1]] = service.DNSCache{
								cache.A,
								cache.AAAA,
								cache.Server,
								&proxy.ProxyInfo{proxyType, ttl, mss, addrlist, option},
							}
						} else {
							service.CacheMap[config[1]] = service.DNSCache{nil, nil, nil,
								&proxy.ProxyInfo{proxyType, ttl, mss, addrlist, option},
							}
						}
					}
				} else {
					var index uint64
					if IP[0] == 0x00 {
						index = uint64(binary.BigEndian.Uint32(IP[12:16]))
					} else {
						index = binary.BigEndian.Uint64(IP[:8])
					}
					service.ProxyMap[index] = &proxy.ProxyInfo{proxyType, ttl, mss, addrlist, option}
				}
			} else if configType[0] == "service" {
				if configType[1] == "socks" {
					serverAddr, err := net.ResolveTCPAddr("tcp", config[2])
					if err != nil {
						log.Println(line)
						return nil
					}
					option := ""
					if len(config) > 3 {
						option = config[3]
					}
					go service.SocksProxy(*serverAddr, config[1], option)
				} else if configType[1] == "http" {
					serverAddr, err := net.ResolveTCPAddr("tcp", config[2])
					if err != nil {
						log.Println(line)
						return nil
					}
					go service.HTTPProxy(*serverAddr)
				} else if configType[1] == "reverse" {
					serverAddr, err := net.ResolveTCPAddr("tcp", config[2])
					if err != nil {
						log.Println(line)
						return nil
					}
					go service.ReverseProxy(*serverAddr)
				} else if configType[1] == "tcp" {
					serverAddr, err := net.ResolveTCPAddr("tcp", config[2])
					if err != nil {
						log.Println(line, err)
						return nil
					}
					go service.TCPMapping(*serverAddr, config[1])
				} else if configType[1] == "tfo" {
					serverAddr, err := net.ResolveTCPAddr("tcp", config[2])
					if err != nil {
						log.Println(line, err)
						return nil
					}
					go service.TFOMapping(*serverAddr, config[1])
				} else if configType[1] == "udp" {
					serverAddr, err := net.ResolveUDPAddr("udp", config[2])
					if err != nil {
						tmp := strings.SplitN(config[2], ":", 2)
						ief, err := net.InterfaceByName(tmp[0])
						if err != nil {
							log.Println(line, tmp, err)
							return nil
						}
						addrs, err := ief.Addrs()
						if err != nil {
							log.Println(line, err)
							return nil
						}

						port, err := strconv.Atoi(tmp[1])
						if err != nil {
							log.Println(line, err)
							return nil
						}

						serverAddr = &net.UDPAddr{
							IP:   addrs[0].(*net.IPNet).IP,
							Port: port,
						}
					}
					if config[1][0] == ':' {
						go service.UDPMapping2(*serverAddr, "127.0.0.1"+config[1])
					} else {
						go service.UDPMapping(*serverAddr, config[1])
					}
				} else {
					log.Println(line)
				}
			}
		} else {
			var err error = nil
			if configType[0] == "server" {
				addrlist := make([]net.UDPAddr, 0)
				for _, addr := range strings.Split(configType[1], "|") {
					addr += ":53"
					serverAddr, _ := net.ResolveUDPAddr("udp", addr)
					addrlist = append(addrlist, *serverAddr)
				}
				service.DefaultServer = service.DNSCache{
					nil,
					nil,
					&service.ServerInfo{dns.UDP, addrlist, ""},
					nil,
				}
			} else if configType[0] == "port" {
				//DNSAddress, _ = net.ResolveUDPAddr("udp", ":"+configType[1])
				DNSPort, err = strconv.Atoi(configType[1])
			} else if configType[0] == "listen-address" {
				for _, addr := range strings.Split(configType[1], ",") {
					if strings.HasPrefix(addr, "[") {
						if !strings.Contains(addr, "]:") {
							addr += ":" + strconv.Itoa(DNSPort)
						}
					} else {
						if !strings.Contains(addr, ":") {
							addr += ":" + strconv.Itoa(DNSPort)
						}
					}
					serverAddr, _ := net.ResolveUDPAddr("udp", addr)
					ListenAddress = append(ListenAddress, serverAddr)
				}
			} else if configType[0] == "proxy" {
				ProxyAddress, err = net.ResolveTCPAddr("tcp", configType[1])
			} else if configType[0] == "clients" {
				for _, addr := range strings.Split(configType[1], "|") {
					service.ProxyClients[addr] = true
				}
			} else if configType[0] == "min-cache-ttl" {
				service.MinCacheTTL, err = strconv.Atoi(configType[1])
			} else if configType[0] == "default-fake-ttl" {
				var fakeTTL int
				fakeTTL, err = strconv.Atoi(configType[1])
				service.DefaultFakeTTL = uint8(fakeTTL)
			} else if configType[0] == "domain-needed" {
				service.DomainNeeded = true
			} else if configType[0] == "bogus-priv" {
				service.BogusPriv = true
			}
			if err != nil {
				log.Println(configType[1])
				return err
			}
		}
	}
	return nil
}

func handleLoadConfigFile(path string) error {
	if strings.HasPrefix(path, "http://") {
		response, err := http.Get(path)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		body, _ := ioutil.ReadAll(response.Body)

		for _, line := range strings.Split(string(body), "\n") {
			_ = handleLoadConfig(string(line))
		}
	} else {
		conf, err := os.Open(path)
		if err != nil {
			var dir string
			dir, err = filepath.Abs(filepath.Dir(os.Args[0]))
			if err != nil {
				return err
			}
			dir += "/" + path
			conf, err = os.Open(dir)
			if err != nil {
				return err
			}
		}
		defer conf.Close()
		br := bufio.NewReader(conf)
		for {
			line, _, err := br.ReadLine()
			if err == io.EOF {
				break
			}
			_ = handleLoadConfig(string(line))
		}
	}

	return nil
}

func main() {
	runtime.GOMAXPROCS(1)

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	Args := os.Args
	fmt.Println(Args)

	argcount := len(Args)

	//Config
	service.CacheMap = make(map[string]service.DNSCache)
	service.ProxyMap = make(map[uint64]*proxy.ProxyInfo)
	service.ProxyClients = make(map[string]bool)

	if argcount > 1 {

		for _, arg := range Args[:] {
			if arg == "-4" {
				service.DNSMode = 4
			} else if arg == "-6" {
				service.DNSMode = 6
			} else if arg == "-r" {
				service.RandPort = true
			} else if arg == "--log" {
				service.LogEnable = true
			} else {
				err := handleLoadConfigFile(arg)
				if err != nil {
					log.Println(err)
					return
				}
			}
		}
	} else {
		//fmt.Println("-4 IPv4\r\n-6 IPv6\r\n-r Random DNS Port\r\n")
		//return

		service.DNSMode = 4
		err := handleLoadConfigFile("pino.conf")
		if err != nil {
			log.Println(err)
			return
		}
	}

	if DNSPort != 0 {
		if ProxyAddress != nil {
			if service.LogEnable {
				fmt.Println(*ProxyAddress)
			}
			go func() {
				for {
					err := service.PinocchioProxy(*ProxyAddress)
					if err != nil {
						time.Sleep(time.Second * 3)
					}
				}
			}()
		}

		if len(ListenAddress) > 0 {
			for i := (len(ListenAddress) - 1); i > 0; i-- {
				if service.LogEnable {
					fmt.Println("DNSServer:", ListenAddress[i])
				}
				go service.PinocchioDNS(*ListenAddress[i])
			}
			if service.LogEnable {
				fmt.Println("DNSServer:", ListenAddress[0])
			}

			err := service.PinocchioDNS(*ListenAddress[0])
			if err != nil {
				log.Println(err)
			}
		} else {
			addr, err := net.ResolveUDPAddr("udp", ":"+strconv.Itoa(DNSPort))
			err = service.PinocchioDNS(*addr)
			if err != nil {
				log.Println(err)
			}
		}
	} else {
		addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:53")
		err = service.PinocchioDNS(*addr)
		if err != nil {
			log.Println(err)
		}
	}
}
