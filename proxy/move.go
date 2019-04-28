// +build !windows

package proxy

import (
	"log"
	"math/rand"
	"net"
	"syscall"
)

func MoveProxyHost(serverAddrList []AddrInfo, client net.Conn, host string, port int, mss int, headdata []byte) {
	defer client.Close()
	var server handle
	var err error

	data := make([]byte, BUFFER_SIZE)
	n := 0
	if len(headdata) > 0 {
		copy(data[:], headdata[:])
		n = len(headdata)
	} else {
		n, err = client.Read(data)
		if err != nil {
			log.Println(err)
			return
		}
	}

	if len(serverAddrList) == 0 {
		if MoveHttp(string(data), "", client) {
			return
		}
	} else {
		serverAddr := serverAddrList[rand.Intn(len(serverAddrList))].Address
		IP := serverAddr.IP

		if MoveHttp(string(data), host, client) {
			return
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

		err = Connect(server, sa)
		if err != nil {
			log.Println(host, err)
			return
		}
	}

	n, err = syscall.Write(server, data[:n])
	if err != nil {
		log.Println(host, err)
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
			log.Println(err)
			return
		}
	}
}
