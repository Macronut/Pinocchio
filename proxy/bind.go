// +build !windows

package proxy

import (
	"log"
	"math/rand"
	"net"
	"strings"
	"syscall"
)

const TCP_USER_TIMEOUT = 0x12

// Is p all zeros?
func isZeros(p net.IP) bool {
	for i := 0; i < len(p); i++ {
		if p[i] != 0 {
			return false
		}
	}
	return true
}

func BindProxyAddr(serverAddrList []AddrInfo, option string, client net.Conn, address *net.TCPAddr, mss int, tfo bool) {
	defer client.Close()
	var server handle
	var err error
	port := address.Port

	data := make([]byte, BUFFER_SIZE)
	n, err := client.Read(data)
	if err != nil {
		log.Println(err)
		return
	}

	addrCount := len(serverAddrList)
	var serverAddr net.TCPAddr
	var iface string
	if addrCount > 0 {
		addressInfo := serverAddrList[rand.Intn(addrCount)]
		if len(addressInfo.Interface) == 0 {
			ifaces := strings.Split(option, "|")
			iface = ifaces[rand.Intn(len(ifaces))]
		} else {
			iface = addressInfo.Interface
		}
		serverAddr = addressInfo.Address
	} else {
		serverAddr = *address
		ifaces := strings.Split(option, "|")
		iface = ifaces[rand.Intn(len(ifaces))]
	}

	IP := serverAddr.IP

	if isZeros(IP) {
		IP = address.IP
	}

	var sa syscall.Sockaddr
	ip4 := IP.To4()
	if ip4 != nil {
		var addr [4]byte
		copy(addr[:4], ip4)
		sa = &syscall.SockaddrInet4{Addr: addr, Port: port}
		server, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
		_, err = BindInterface(server, iface)
		if err != nil {
			log.Println(err)
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
			return
		}
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
		log.Println(err)
		return
	}

	if err != nil {
		log.Println(err)
		return
	}

	if !tfo {
		n, err = syscall.Write(server, data[:n])
		if err != nil {
			log.Println(err)
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

func BindProxyHost(serverAddrList []AddrInfo, option string, client net.Conn, host string, port int, mss int, headdata []byte) {
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
		ifaces := strings.Split(option, "|")
		iface = ifaces[rand.Intn(len(ifaces))]
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
			log.Println(err, ":", iface)
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
			return
		}
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

	SetTCPKeepAlive(server, true)

	if err != nil {
		log.Println(err)
		return
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
			return
		}
	}

	_, err = syscall.Write(server, data[:n])
	if err != nil {
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
			log.Println(host, err)
			return
		}
	}
}
