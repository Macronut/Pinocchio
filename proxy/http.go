package proxy

import (
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
)

func HTTPProxyHost(serverAddrList []AddrInfo, client net.Conn, host string, port int) {
	addr, err := net.ResolveTCPAddr("tcp", ":0")
	serverAddr := serverAddrList[rand.Intn(len(serverAddrList))].Address
	server, err := net.DialTCP("tcp", addr, &serverAddr)
	if err != nil {
		log.Println(err)
		return
	}
	defer server.Close()

	err = server.SetKeepAlive(true)
	if err != nil {
		log.Println(err)
		return
	}

	var b [2048]byte
	data := make([]byte, BUFFER_SIZE)
	n, err := client.Read(data)
	if err != nil {
		log.Println(err)
		return
	}

	request := string(data[:n])

	if n < 4 {
		n, err := client.Read(data)
		if err != nil {
			log.Println(err)
			return
		} else if n == 0 {
			return
		}
		request += string(data[:n])
	}

	if request[:4] == "GET " || request[:4] == "POST" || request[:4] == "HEAD" {
		go Forward(server, client)

		dataSize := -1
		for {
			if dataSize > -1 {
				n, err = client.Read(data)
				if err != nil {
					return
				}

				if dataSize > 0 {
					if n < dataSize {
						_, err = server.Write(data[:n])
						dataSize -= n
						continue
					} else {
						_, err = server.Write(data[:dataSize])
						request = string(data[dataSize:n])
						dataSize = 0
					}
				} else {
					request += string(data[:n])
				}
			}

			method := ""
			resource := ""
			end := strings.Index(request, "\r\n\r\n")
			if end > 0 {
				split := strings.Index(request, " ")
				if split > 0 {
					method = request[:split]
					contentLen := strings.Index(request, "Content-Length: ")
					if contentLen > 0 {
						contentLen += 16
						contentLenEnd := strings.Index(request[contentLen:], "\r\n")
						if contentLenEnd <= 0 {
							return
						}
						contentLenEnd += contentLen
						dataSize, err = strconv.Atoi(request[contentLen:contentLenEnd])
						if err != nil {
							log.Println(err)
							return
						}
					} else {
						dataSize = 0
					}
					split++
					end += 4

					if len(request[end:]) < dataSize {
						dataSize -= len(request[end:])
						resource = request[split:]
						request = ""
					} else {
						resource = request[split : end+dataSize]
						request = request[end+dataSize:]
						dataSize = 0
					}
				} else {
					continue
				}
			} else {
				continue
			}

			proxy_request := ""
			if port == 80 {
				proxy_request = method + " " + "http://" + host + resource
			} else {
				proxy_request = method + " " + "http://" + host + ":" + strconv.Itoa(port) + resource
			}

			//log.Println(proxy_request)

			_, err = server.Write([]byte(proxy_request))
			if err != nil {
				log.Println(err)
				return
			}
		}
	} else {
		_, err = server.Write([]byte("CONNECT " + host + ":" + strconv.Itoa(port) + " HTTP/1.1\r\n\r\n"))

		if err != nil {
			log.Println(err)
			return
		} else {
			n, err := server.Read(b[:])
			if err != nil {
				log.Println(err)
				return
			}

			if string(b[:13]) != "HTTP/1.1 200 " {
				log.Println(string(b[:n]))
				return
			}
		}

		_, err = server.Write(data[:n])
		if err != nil {
			log.Println(err)
			return
		}

		go Forward(server, client)
		Forward(client, server)
	}
}

func HTTPProxyAddr(serverAddrList []AddrInfo, client net.Conn, address *net.TCPAddr) {
	HTTPProxyHost(serverAddrList, client, address.IP.String(), address.Port)
}
