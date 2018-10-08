package proxy

import (
	"log"
	"math/rand"
	"net"
	"strings"
	"syscall"
)

func MoveHttps(data []byte, client net.Conn) bool {
	if data[0] == 0x16 {
		return false
	}
	header := string(data)
	if header[:4] != "GET " {
		return false
	}
	d := make([]byte, 1024)
	start := strings.Index(header, "Host: ") + 6
	end := strings.Index(header[start:], "\r\n") + start
	n := 0
	copy(d[:], []byte("HTTP/1.1 301 TLS Redirect\r\nLocation: https://"))
	n += 45
	copy(d[n:], []byte(header[start:end]))
	n += end - start
	start = strings.Index(header, " /") + 1
	end = strings.Index(header[start:], " ") + start
	copy(d[n:], []byte(header[start:end]))
	n += end - start
	copy(d[n:], []byte("\r\nContent-Length: 0\r\n\r\n"))
	n += 23
	client.Write(d[:n])
	return true
}

func MoveHttp(header string, host string, client net.Conn) bool {
	data := make([]byte, BUFFER_SIZE)
	n := 0
	if host == "" {
		if header[:4] != "GET " {
			return true
		}
		copy(data[:], []byte("HTTP/1.1 200 OK"))
		n += 15
	} else if host == "https" {
		if header[:4] != "GET " {
			return false
		}
		copy(data[:], []byte("HTTP/1.1 302 Found\r\nLocation: https://"))
		n += 38

		start := strings.Index(header, "Host: ") + 6
		end := strings.Index(header[start:], "\r\n") + start
		copy(data[n:], []byte(header[start:end]))
		n += end - start

		start = 4
		end = strings.Index(header[start:], " ") + start
		copy(data[n:], []byte(header[start:end]))
		n += end - start
	} else {
		if header[:4] != "GET " {
			return false
		}
		copy(data[:], []byte("HTTP/1.1 302 Found\r\nLocation: "))
		n += 30
		copy(data[n:], []byte(host))
		n += len(host)

		start := 4
		end := strings.Index(header[start:], " ") + start
		copy(data[n:], []byte(header[start:end]))
		n += end - start
	}

	copy(data[n:], []byte("\r\nCache-Control: private\r\nServer: pinocchio\r\nContent-Length: 0\r\n\r\n"))
	n += 66
	client.Write(data[:n])
	return true
}

func MoveProxyHost(serverAddrList []net.TCPAddr, client net.Conn, host string, port int, mss int, tfo bool) {
	defer client.Close()
	var server handle
	var err error

	data := make([]byte, BUFFER_SIZE)
	n, err := client.Read(data)
	if err != nil {
		log.Println(err)
		return
	}

	if len(serverAddrList) == 0 {
		if MoveHttp(string(data), "", client) {
			return
		}
	} else {
		serverAddr := serverAddrList[rand.Intn(len(serverAddrList))]
		IP := serverAddr.IP
		if serverAddr.Port != 0 {
			port = serverAddr.Port
		}

		if host != "" {
			if MoveHttp(string(data), host, client) {
				return
			}
		}

		var sa syscall.Sockaddr
		ip4 := IP.To4()
		if ip4 != nil {
			var addr [4]byte
			copy(addr[:4], ip4)
			sa = &syscall.SockaddrInet4{Addr: addr, Port: port}
			server, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
		} else {
			var addr [16]byte
			copy(addr[:16], IP)
			sa = &syscall.SockaddrInet6{Addr: addr, Port: port}
			server, err = syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, 0)
		}

		if mss > 0 {
			err = SetTCPMaxSeg(server, mss)
			if err != nil {
				log.Println(err)
				return
			}
		}

		if tfo {
			err = ConnectEx(server, data[:n], sa)
		} else {
			err = Connect(server, sa)
		}
		if err != nil {
			log.Println(host, err)
			return
		}
	}

	if !tfo {
		n, err = syscall.Write(server, data[:n])
		if err != nil {
			log.Println(host, err)
			return
		}
	}

	go ForwardFromSocket(server, client)

	for {
		n, err := client.Read(data)
		if n <= 0 {
			return
		}
		n, err = SendAll(server, data[:n])
		if err != nil {
			log.Println(err)
			return
		}
	}
}
