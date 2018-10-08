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

func BindProxyAddr(serverAddrList []net.TCPAddr, option string, client net.Conn, address *net.TCPAddr, mss int, tfo bool) {
	defer client.Close()
	var server handle
	var err error
	var bindsa4 syscall.Sockaddr = nil
	var bindsa6 syscall.Sockaddr = nil
	port := address.Port

	data := make([]byte, BUFFER_SIZE)
	n, err := client.Read(data)
	if err != nil {
		log.Println(err)
		return
	}

	if MoveHttps(data, client) {
		return
	}

	if option != "" {
		faces := make([]string, 0)
		for _, face := range strings.Split(option, "|") {
			faces = append(faces, face)
		}
		face := faces[rand.Intn(len(faces))]

		inf, err := net.InterfaceByName(face)
		if err == nil {
			addrs, _ := inf.Addrs()
			for _, addr := range addrs {
				bindaddr, ok := addr.(*net.IPNet)
				if ok {
					if bindaddr.IP.To4() != nil {
						if bindsa4 == nil {
							var addr [4]byte
							copy(addr[:4], bindaddr.IP[12:])
							bindsa4 = &syscall.SockaddrInet4{Addr: addr, Port: 0}
						}
					} else {
						if bindsa6 == nil {
							var addr [16]byte
							copy(addr[:16], bindaddr.IP)
							bindsa6 = &syscall.SockaddrInet6{Addr: addr, Port: 0}
						}
					}
				} else {
					return
				}
			}
		} else {
			log.Println(err, face)
		}
	}

	serverAddr := serverAddrList[rand.Intn(len(serverAddrList))]
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
		if bindsa4 != nil {
			err = syscall.Bind(server, bindsa4)
			if err != nil {
				log.Println(err)
				return
			}
		}
	} else {
		var addr [16]byte
		copy(addr[:16], IP)
		sa = &syscall.SockaddrInet6{Addr: addr, Port: port}
		server, err = syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, 0)
		if bindsa6 != nil {
			err = syscall.Bind(server, bindsa6)
			if err != nil {
				log.Println(err)
				return
			}
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

func BindProxyHost(serverAddrList []net.TCPAddr, option string, client net.Conn, host string, port int, mss int, tfo bool) {
	defer client.Close()

	serverAddrCount := len(serverAddrList)
	if serverAddrCount == 0 {
		return
	}

	var server handle
	var err error
	var bindsa4 syscall.Sockaddr = nil
	var bindsa6 syscall.Sockaddr = nil

	data := make([]byte, BUFFER_SIZE)
	n, err := client.Read(data)
	if err != nil {
		log.Println(err)
		return
	}

	if option != "" {
		faces := make([]string, 0)
		for _, face := range strings.Split(option, "|") {
			faces = append(faces, face)
		}
		if len(faces) > 0 {
			face := faces[rand.Intn(len(faces))]

			inf, err := net.InterfaceByName(face)
			if err == nil {
				addrs, _ := inf.Addrs()
				for _, addr := range addrs {
					bindaddr, ok := addr.(*net.IPNet)
					if ok {
						if bindaddr.IP.To4() != nil {
							if bindsa4 == nil {
								var addr [4]byte
								copy(addr[:4], bindaddr.IP[12:])
								bindsa4 = &syscall.SockaddrInet4{Addr: addr, Port: 0}
							}
						} else {
							if bindsa6 == nil {
								var addr [16]byte
								copy(addr[:16], bindaddr.IP)
								bindsa6 = &syscall.SockaddrInet6{Addr: addr, Port: 0}
							}
						}
					} else {
						return
					}
				}
			} else {
				log.Println(err, face)
			}
		}
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
		if bindsa4 != nil {
			err = syscall.Bind(server, bindsa4)
			if err != nil {
				log.Println(err)
				return
			}
		}
	} else {
		var addr [16]byte
		copy(addr[:16], IP)
		sa = &syscall.SockaddrInet6{Addr: addr, Port: port}
		server, err = syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, 0)
		if bindsa6 != nil {
			err = syscall.Bind(server, bindsa6)
			if err != nil {
				log.Println(err)
				return
			}
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
		log.Println(host, err)
		return
	}

	SetTCPKeepAlive(server, true)

	if err != nil {
		log.Println(err)
		return
	}

	if !tfo {
		if mss > 0 {
			hostOffset := strings.Index(string(data[:n]), host) / 2
			_, err = syscall.Write(server, data[:hostOffset])
			_, err = syscall.Write(server, data[hostOffset:n])
		} else {
			_, err = syscall.Write(server, data[:n])
		}

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
			log.Println(host, err)
			return
		}
	}
}
