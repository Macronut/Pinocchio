// +build !windows

package proxy

import (
	"log"
	"math/rand"
	"net"
	"strings"
	"syscall"
	"time"

	"../net/ipv6"
	"../net/tcp"
	//"sync"
)

const IPV6_AUTOFLOWLABEL int = 70

type TCPInfo6 struct {
	SeqNum uint32
	AckNum uint32
	Src    [16]byte
	Port   uint16
}

var PortChan6 [65536](chan TCPInfo6)

func MystifyConnect6(fd handle, sa syscall.Sockaddr, bindsa syscall.Sockaddr, timeout int) (TCPInfo6, error) {
	raw_fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	defer syscall.Close(raw_fd)

	var connInfo = TCPInfo6{0, 0, [16]byte{0}, 0}

	if err != nil {
		log.Println(err)
		return connInfo, err
	}

	if bindsa != nil {
		err = syscall.Bind(raw_fd, bindsa)
		if err != nil {
			return connInfo, err
		}
	}
	err = syscall.Connect(raw_fd, sa)
	if err != nil {
		log.Println(err)
		return connInfo, err
	}

	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, IPV6_AUTOFLOWLABEL, 0)
	if err != nil {
		log.Println(err)
		return connInfo, err
	}

	err = syscall.SetNonblock(fd, true)
	err = syscall.Connect(fd, sa)
	if err != syscall.EINPROGRESS {
		log.Println(err, sa)
		return connInfo, err
	}

	var sockaddr *syscall.SockaddrInet6
	sockname, err := syscall.Getsockname(fd)
	if err != nil {
		log.Println(err)
		return connInfo, err
	}
	switch sockname.(type) {
	case *syscall.SockaddrInet6:
		sockaddr = sockname.(*syscall.SockaddrInet6)
	default:
		return connInfo, err
	}

	rawbuf := make([]byte, 1500)

	ch := make(chan TCPInfo6)
	sockPort := uint16(sockaddr.Port)
	PortChan6[sockPort] = ch
	defer func() {
		PortChan6[sockPort] = nil
	}()

	go func() {
		for {
			buflen, err := syscall.Read(raw_fd, rawbuf)
			if err != nil {
				return
			}
			if buflen < 40 {
				continue
			}

			var tcpheader tcp.Header
			err = tcpheader.Parse(rawbuf[:buflen])
			if err != nil {
				log.Println(err)
				continue
			}

			if tcpheader.Flags != tcp.FlagSYN|tcp.FlagACK {
				continue
			}

			if tcpheader.DPort == sockPort {
				ch <- TCPInfo6{tcpheader.AckNum, tcpheader.SeqNum + 1, sockaddr.Addr, tcpheader.DPort}
				break
			} else {
				pch := PortChan6[tcpheader.DPort]
				if pch != nil {
					pch <- TCPInfo6{tcpheader.AckNum, tcpheader.SeqNum + 1, sockaddr.Addr, tcpheader.DPort}
				}
			}
		}
	}()
	select {
	case res := <-ch:
		connInfo = res
	case <-time.After(time.Second * time.Duration(timeout)):
		return connInfo, syscall.ETIMEDOUT
	}

	err = syscall.SetNonblock(fd, false)
	err = syscall.SetsockoptInt(fd, syscall.SOL_TCP, syscall.TCP_NODELAY, 1)

	return connInfo, nil
}

func MystifySend6(fd handle, data []byte, sa syscall.Sockaddr, ttl int, host string, connInfo TCPInfo6, md5 bool) error {
	var ipheader ipv6.Header
	var tcpheader tcp.Header
	sockPort := connInfo.Port
	sa6 := *sa.(*syscall.SockaddrInet6)

	ipheader.Version = ipv6.Version
	ipheader.TrafficClass = 0
	ipheader.FlowLabel = 0
	ipheader.PayloadLen = tcp.HeaderLen + len(data) + 18
	ipheader.NextHeader = 6
	ipheader.HopLimit = ttl
	ipheader.Src = connInfo.Src[:16]
	ipheader.Dst = sa6.Addr[:16]

	tcpheader.SPort = uint16(sockPort)
	tcpheader.DPort = uint16(sa6.Port)
	tcpheader.Offset = 5
	tcpheader.Flags = tcp.FlagPSH | tcp.FlagACK
	tcpheader.WinSize = 640
	tcpheader.UrgPointer = 0

	if md5 {
		tcpheader.Offset += 5
		tcpheader.Options = []byte{19, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	} else {
		tcpheader.Options = nil
	}

	sa6.Port = 0

	totalLen := ipv6.HeaderLen + ipheader.PayloadLen

	rawbuf := make([]byte, totalLen)
	fakedata := make([]byte, len(data))
	hostbyte := []byte(host)

	psh := tcp.PseudoHeader{ipheader.Src, ipheader.Dst, 6, uint16(ipheader.PayloadLen)}
	pshbyte, err := psh.Marshal()
	if err != nil {
		log.Println(host, err)
		return err
	}
	tcpheader.SeqNum = connInfo.SeqNum
	tcpheader.AckNum = connInfo.AckNum
	tcpbyte, err := tcpheader.MarshalWithData(pshbyte, fakedata)
	if err != nil {
		log.Println(host, err)
		return err
	}
	ipbyte, err := ipheader.Marshal()
	if err != nil {
		log.Println(host, err)
		return err
	}
	copy(rawbuf[:], ipbyte)
	copy(rawbuf[ipv6.HeaderLen:], tcpbyte)

	raw_fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	defer syscall.Close(raw_fd)

	err = syscall.Sendto(raw_fd, rawbuf[:totalLen], 0, &sa6)
	if err != nil {
		log.Println(host, err)
		return err
	}

	hostOffset := 0
	if len(host) > 0 {
		off := 0
		for i := 0; i < len(data); i++ {
			if data[i] == hostbyte[off] {
				off++
				if off == len(hostbyte) {
					hostOffset = i
					break
				}
			} else {
				off = 0
			}
		}
		if hostOffset > 0 {
			hostOffset -= len(hostbyte) / 2
			_, err = syscall.Write(fd, data[:hostOffset])
			if err != nil {
				return err
			}
			err = syscall.Sendto(raw_fd, rawbuf[:totalLen], 0, &sa6)
			if err != nil {
				log.Println(host, err)
				return err
			}
		}
	}

	_, err = syscall.Write(fd, data[hostOffset:])
	if err != nil {
		log.Println(host, err, sa)
		return err
	}
	return nil
}

func MystifyProxy6(serverAddrList []AddrInfo, option string, client net.Conn, host string, port int, ttl int, mss int, md5 bool, headdata []byte) {
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

	var sa syscall.Sockaddr
	var addr [16]byte
	copy(addr[:16], IP)
	sa = &syscall.SockaddrInet6{Addr: addr, Port: port}
	server, err = syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, 0)
	if err != nil {
		log.Println(host, err)
	}
	defer syscall.Close(server)

	bindsa, err := BindInterface(server, iface)
	if bindsa == nil || err != nil {
		log.Println(host, err)
		return
	}

	if mss > 87 {
		err = SetTCPMaxSeg(server, mss)
		if err != nil {
			log.Println(err)
			return
		}
	}

	var connInfo TCPInfo6
	connInfo, err = MystifyConnect6(server, sa, bindsa, 10)
	if err != nil {
		log.Println(err)
		return
	}

	data := make([]byte, 1460)
	n := 0

	if len(headdata) > 0 {
		copy(data[:], headdata[:])
		n = len(headdata)
	} else {
		n, err = client.Read(data)
		if err != nil {
			return
		}
	}

	if MoveHttps(data, client) {
		return
	}
	/*
		sockname, err := syscall.Getsockname(server)
		if err != nil {
			log.Println(err)
			return
		}
	*/

	if mss > 0 {
		err = MystifySend6(server, data[:n], sa, ttl, host, connInfo, md5)
	} else {
		err = MystifySend6(server, data[:n], sa, ttl, "", connInfo, md5)
	}

	if err != nil {
		log.Println(host, serverAddr, err)
		return
	}

	/*
		if SetTCPKeepAlive(server, true) != nil {
			log.Println(err)
			return
		}
	*/

	go ForwardFromSocket(server, client)

	if mss > 87 {
		//Restore MSS
		n, err = client.Read(data)
		if n <= 0 {
			return
		}

		if mss > 0 {
			err = SetTCPMaxSeg(server, 1280)
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
		if n <= 0 {
			return
		}
		n, err = SendAll(server, data[:n])
		if err != nil {
			return
		}
	}
}

func MystifyProxyHTTP6(serverAddrList []AddrInfo, option string, client net.Conn, host string, port int, ttl int, mss int, md5 bool) {
	defer client.Close()

	serverAddrCount := len(serverAddrList)
	if serverAddrCount == 0 {
		return
	}

	var server handle
	var err error

	addrInfo := serverAddrList[rand.Intn(serverAddrCount)]

	var iface string
	if len(addrInfo.Interface) == 0 {
		ifaces := strings.Split(option, "|")
		iface = ifaces[rand.Intn(len(ifaces))]
	} else {
		iface = addrInfo.Interface
	}

	serverAddr := addrInfo.Address
	IP := serverAddr.IP

	var sa syscall.Sockaddr
	var addr [16]byte
	copy(addr[:16], IP)
	sa = &syscall.SockaddrInet6{Addr: addr, Port: port}
	server, err = syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, 0)
	if err != nil {
		log.Println(host, err)
	}
	defer syscall.Close(server)

	bindsa, err := BindInterface(server, iface)
	if err != nil {
		log.Println(host, iface, err)
		return
	}

	if mss > 0 {
		err = SetTCPMaxSeg(server, mss)
		if err != nil {
			log.Println(err)
			return
		}
	}

	var connInfo TCPInfo6
	connInfo, err = MystifyConnect6(server, sa, bindsa, 6)

	data := make([]byte, 1460)

	go ForwardFromSocket(server, client)
	for {
		n, err := client.Read(data)
		if err != nil {
			return
		}

		requestValue := strings.Split(string(data[:n]), "\r\n")
		request := ""
		for _, value := range requestValue {
			if strings.HasPrefix(value, "Referer: ") {
				continue
			} else if strings.HasPrefix(value, "Cookie: ") {
				continue
			}

			request += string(value) + "\r\n"
		}

		err = MystifySend6(server, []byte(request), sa, ttl, host, connInfo, md5)
		connInfo.SeqNum += uint32(len(request))
		if err != nil {
			return
		}
	}
}
