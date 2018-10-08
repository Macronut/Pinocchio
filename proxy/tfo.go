package proxy

import (
	"log"
	"math/rand"
	"net"

	"syscall"
)

func ForceTFOProxyHost(serverAddrList []net.TCPAddr, option string, client net.Conn, host string, port int, mss int) {
	defer client.Close()

	serverAddrCount := len(serverAddrList)
	if serverAddrCount == 0 {
		return
	}

	var server handle
	var err error

	data := make([]byte, 1460)
	n, err := client.Read(data)
	if err != nil {
		return
	}

	if MoveHttps(data[:n], client) {
		return
	}

	serverAddr := serverAddrList[rand.Intn(serverAddrCount)]
	IP := serverAddr.IP

	var sa syscall.Sockaddr
	ip4 := IP.To4()
	if ip4 != nil {
		var addr [4]byte
		copy(addr[:4], ip4[:4])
		sa = &syscall.SockaddrInet4{Addr: addr, Port: port}
		server, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	} else {
		var addr [16]byte
		copy(addr[:16], IP)
		sa = &syscall.SockaddrInet6{Addr: addr, Port: port}
		server, err = syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, 0)
	}
	if err != nil {
		log.Println(host, err)
	}

	err = ConnectEx(server, []byte("GET / HTTP/1.1\r\n\r\n"), sa)
	if err != nil {
		return
	}
	recv := make([]byte, 325)
	_, err = syscall.Read(server, recv)
	syscall.Close(server)

	if ip4 != nil {
		server, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	} else {
		server, err = syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, 0)
	}
	defer syscall.Close(server)

	if mss > 0 {
		if SetTCPMaxSeg(server, mss) != nil {
			log.Println(err)
			return
		}
	}

	err = ConnectEx(server, data[:n], sa)
	if err != nil {
		log.Println(host, err)
		return
	}

	if SetTCPKeepAlive(server, true) != nil {
		log.Println(err)
		return
	}

	go ForwardFromSocket(server, client)

	for {
		n, err := client.Read(data)
		if n <= 0 {
			return
		}
		n, err = SendAll(server, data[:n])
		if err != nil {
			return
		}
	}
}
