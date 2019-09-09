// +build !windows

package proxy

import (
	"log"
	"math/rand"
	"net"
	"syscall"
	"time"
)

func TFOProxyHost(serverAddrList []AddrInfo, option string, client net.Conn, host string, port int, mss int, headdata []byte) {
	defer client.Close()

	serverAddrCount := len(serverAddrList)
	if serverAddrCount == 0 {
		return
	}

	var server handle
	var err error

	addressInfo := serverAddrList[rand.Intn(serverAddrCount)]

	var iface string
	if len(addressInfo.Interface) == 0 {
		iface = option
	} else {
		iface = addressInfo.Interface
	}

	serverAddr := addressInfo.Address
	IP := serverAddr.IP
	if serverAddr.Port != 0 {
		port = serverAddr.Port
	}

	var sa syscall.Sockaddr
	ip4 := IP.To4()
	if ip4 != nil {
		var addr [4]byte
		copy(addr[:4], ip4[:4])
		sa = &syscall.SockaddrInet4{Addr: addr, Port: port}
		server, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
		_, err = BindInterface(server, iface)
		if err != nil {
			log.Println(err)
			syscall.Close(server)
			return
		}
	} else {
		var addr [16]byte
		copy(addr[:16], IP)
		sa = &syscall.SockaddrInet6{Addr: addr, Port: port}
		server, err = syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, 0)
		_, err = BindInterface6(server, iface)
		if err != nil {
			log.Println(err)
			syscall.Close(server)
			return
		}
	}

	if mss > 0 {
		err = SetTCPMaxSeg(server, mss)
		if err != nil {
			log.Println(err)
			syscall.Close(server)
			return
		}
	}

	data := make([]byte, BUFFER_SIZE)
	n := 0
	if len(headdata) > 0 {
		copy(data[:], headdata[:])
		n = len(headdata)
	} else {
		n, err = client.Read(data)
		if err != nil {
			log.Println(err)
			syscall.Close(server)
			return
		}
	}

	err = ConnectEx(server, data[:n], sa)
	if err != nil {
		log.Println(host, err)
		syscall.Close(server)
		return
	}

	go ForwardFromSocket(server, client)

	if mss > 0 {
		//Restore MSS
		n, err = client.Read(data)
		if n <= 0 {
			return
		}

		if mss > 0 {
			err = SetTCPMaxSeg(server, 1452)
			if err != nil {
				log.Println(err)
				return
			}
		}
		n, err = SendAll(server, data[:n])
		if err != nil {
			return
		}
	}

	for {
		n, err := client.Read(data)
		if LogEnable && err != nil {
			log.Println(n, err)
		}

		if n <= 0 {
			syscall.Close(server)
			return
		}

		client.SetReadDeadline(time.Now().Add(CONN_TTL))

		n, err = SendAll(server, data[:n])
		if err != nil {
			log.Println(host, err)
			syscall.Close(server)
			return
		}
	}
}
