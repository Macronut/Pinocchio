// +build !windows

package proxy

import (
	"encoding/binary"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"../net/ipv4"
	"../net/tcp"
)

type TCPInfo struct {
	Local  uint32
	SeqNum uint32
	AckNum uint32
}

func htons(h uint16) uint16 {
	return ((h >> 8) & 0xFF) | ((h & 0xFF) << 8)
}

func ConnectMask(fd handle, data []byte, sa syscall.Sockaddr, ttl int, host string, bindsa syscall.Sockaddr, timeout int) error {
	raw_fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		log.Println(host, err)
		return err
	}

	if bindsa != nil {
		err = syscall.Bind(raw_fd, bindsa)
		if err != nil {
			log.Println(host, err)
			syscall.Close(raw_fd)
			return err
		}
	}
	err = syscall.Connect(raw_fd, sa)
	if err != nil {
		log.Println(host, err)
		syscall.Close(raw_fd)
		return err
	}

	err = syscall.SetNonblock(fd, true)
	err = syscall.Connect(fd, sa)
	if err != syscall.EINPROGRESS {
		log.Println(host, err)
		syscall.Close(raw_fd)
		return err
	}

	var sockaddr *syscall.SockaddrInet4
	sockname, err := syscall.Getsockname(fd)
	if err != nil {
		log.Println(host, err)
		syscall.Close(raw_fd)
		return err
	}
	switch sockname.(type) {
	case *syscall.SockaddrInet4:
		sockaddr = sockname.(*syscall.SockaddrInet4)
	default:
		log.Println(sockaddr)
		syscall.Close(raw_fd)
		return err
	}
	sockPort := uint16(sockaddr.Port)

	rawbuf := make([]byte, 1500)

	var connInfo = TCPInfo{0, 0, 0}
	//startTime := time.Now()
	ch := make(chan TCPInfo)
	go func() {
		for {
			var ipheader ipv4.Header
			var tcpheader tcp.Header

			buflen, err := syscall.Read(raw_fd, rawbuf)
			if err != nil {
				return
			}
			if buflen < 40 {
				continue
			}

			err = ipheader.Parse(rawbuf[:buflen])
			if err != nil {
				log.Println(err)
				continue
			}

			iDstIP := binary.BigEndian.Uint32(ipheader.Dst.To4())
			iSockIP := binary.BigEndian.Uint32(sockaddr.Addr[:4])
			if iDstIP != iSockIP {
				continue
			}

			err = tcpheader.Parse(rawbuf[ipheader.Len:buflen])
			if err != nil {
				log.Println(err)
				continue
			}

			if tcpheader.Flags != tcp.FlagSYN|tcp.FlagACK {
				continue
			}

			if tcpheader.DPort == sockPort {
				ch <- TCPInfo{iDstIP, tcpheader.SeqNum, tcpheader.AckNum}
				break
			}
			//log.Println(host, tcpheader.DPort, sockPort)
		}
	}()
	select {
	case res := <-ch:
		connInfo = res
	case <-time.After(time.Second * time.Duration(timeout)):
		return syscall.ETIMEDOUT
	}
	//log.Println(host, time.Since(startTime))

	syscall.Close(raw_fd)
	err = syscall.SetNonblock(fd, false)
	err = syscall.SetsockoptInt(fd, syscall.SOL_TCP, syscall.TCP_NODELAY, 1)

	raw_fd, _ = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	var ipheader ipv4.Header
	var tcpheader tcp.Header
	ipheader.Version = 4
	ipheader.Len = 20
	ipheader.TOS = 0
	ipheader.TotalLen = 0
	ipheader.ID = 0
	ipheader.Flags = 2
	ipheader.FragOff = 0
	ipheader.TTL = ttl
	ipheader.Protocol = 6
	ipheader.Checksum = 0
	ipheader.Src = sockaddr.Addr[:4]
	ipheader.Dst = sa.(*syscall.SockaddrInet4).Addr[:4]
	ipheader.Options = nil

	tcpheader.SPort = sockPort
	tcpheader.DPort = uint16(sa.(*syscall.SockaddrInet4).Port)
	tcpheader.Offset = 5
	tcpheader.Flags = tcp.FlagPSH | tcp.FlagACK
	tcpheader.WinSize = 640
	tcpheader.UrgPointer = 0
	tcpheader.Options = nil
	//log.Println(ipheader)
	//log.Println(tcpheader)

	fakedata := make([]byte, len(data))
	ipheader.TotalLen = ipv4.HeaderLen + tcp.HeaderLen + len(data)
	psh := tcp.PseudoHeader{ipheader.Src, ipheader.Dst, 6, uint16(tcp.HeaderLen + len(data))}
	pshbyte, err := psh.Marshal()
	tcpheader.SeqNum = connInfo.AckNum
	tcpheader.AckNum = connInfo.SeqNum + 1
	tcpbyte, err := tcpheader.MarshalWithData(pshbyte, fakedata)
	ipbyte, _ := ipheader.Marshal()
	copy(rawbuf[:], ipbyte)
	copy(rawbuf[ipheader.Len:], tcpbyte)
	//time.Sleep(time.Millisecond * 20)
	err = syscall.Sendto(raw_fd, rawbuf[:ipheader.TotalLen], 0, sa)

	hostbyte := []byte(host)
	hostOffset := 0
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
		//time.Sleep(time.Millisecond * 20)
		hostOffset -= len(hostbyte) / 2
		_, err = syscall.Write(fd, data[:hostOffset])
		if err != nil {
			syscall.Close(raw_fd)
			return err
		}
	} else {
		log.Println(host, "NO SNI")
	}

	err = syscall.Sendto(raw_fd, rawbuf[:ipheader.TotalLen], 0, sa)
	if err != nil {
		log.Println(host, err)
		syscall.Close(raw_fd)
		return err
	}
	//time.Sleep(time.Millisecond * 20)
	_, err = syscall.Write(fd, data[hostOffset:])
	if err != nil {
		log.Println(host, err)
		syscall.Close(raw_fd)
		return err
	}
	syscall.Close(raw_fd)
	return nil
}

func TTLProxyHost(serverAddrList []net.TCPAddr, option string, client net.Conn, host string, port int, mss int) {
	defer client.Close()

	serverAddrCount := len(serverAddrList)
	if serverAddrCount == 0 {
		return
	}

	var server handle
	var err error
	var bindsa4 syscall.Sockaddr = nil
	var bindsa6 syscall.Sockaddr = nil

	data := make([]byte, 1460)
	n, err := client.Read(data)
	if err != nil {
		return
	}

	//if MoveHttps(string(data[:n]), client) {
	//	return
	//}

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
	ttl := serverAddr.Port

	var sa syscall.Sockaddr
	ip4 := IP.To4()
	if ip4 != nil {
		var addr [4]byte
		copy(addr[:4], ip4[:4])
		sa = &syscall.SockaddrInet4{Addr: addr, Port: port}
		server, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
		if err != nil {
			log.Println(host, err)
		}
		if bindsa4 != nil {
			err = syscall.Bind(server, bindsa4)
			if err != nil {
				log.Println(host, err)
				return
			}
			/*
				sockname, err := syscall.Getsockname(server)
				if err != nil {
					log.Println(host, err)
					return
				}
				bindsa4 = sockname.(*syscall.SockaddrInet4)
			*/
		}
	} else {
		var addr [16]byte
		copy(addr[:16], IP)
		sa = &syscall.SockaddrInet6{Addr: addr, Port: port}
		server, err = syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, 0)
	}
	defer syscall.Close(server)

	if mss > 0 {
		if SetTCPMaxSeg(server, mss) != nil {
			log.Println(err)
			return
		}
	}

	var bindsa syscall.Sockaddr
	if bindsa4 != nil {
		bindsa = bindsa4
	} else if bindsa6 != nil {
		bindsa = bindsa6
	}

	err = ConnectMask(server, data[:n], sa, ttl, host, bindsa, 2)

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

var RAWIPMutex sync.Mutex

func ConnectMaskS(fd handle, data []byte, sa syscall.Sockaddr, ttl int, host string, bindsa syscall.Sockaddr, timeout int) error {
	hostbyte := []byte(host)
	hostOffset := 0
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
	} else {
		log.Println(host, "NO SNI")
	}

	err := Connect(fd, sa)

	var sockaddr *syscall.SockaddrInet4
	sockname, err := syscall.Getsockname(fd)
	if err != nil {
		log.Println(host, err)
		return err
	}
	switch sockname.(type) {
	case *syscall.SockaddrInet4:
		sockaddr = sockname.(*syscall.SockaddrInet4)
	default:
		log.Println(sockaddr)
		return err
	}
	sockPort := uint16(sockaddr.Port)

	RAWIPMutex.Lock()

	raw_fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))

	if err != nil {
		log.Println(host, err)
		syscall.Close(raw_fd)
		RAWIPMutex.Unlock()
		return err
	}

	_, err = syscall.Write(fd, data[:1])
	if err != nil {
		log.Println(host, err)
		syscall.Close(raw_fd)
		RAWIPMutex.Unlock()
		return err
	}

	rawbuf := make([]byte, 1500)

	var connInfo = TCPInfo{0, 0, 0}
	ch := make(chan TCPInfo)
	go func() {
		for {
			var ipheader ipv4.Header
			var tcpheader tcp.Header

			buflen, _, err := syscall.Recvfrom(raw_fd, rawbuf, 0)
			if err != nil {
				syscall.Close(raw_fd)
				return
			}

			if buflen < 40 {
				continue
			}

			err = ipheader.Parse(rawbuf[14:buflen])
			if err != nil {
				log.Println(err)
				continue
			}

			iDstIP := binary.BigEndian.Uint32(ipheader.Dst.To4())
			iRemoteIP := binary.BigEndian.Uint32(sa.(*syscall.SockaddrInet4).Addr[:4])
			if iDstIP != iRemoteIP {
				continue
			}

			iSrcIP := binary.BigEndian.Uint32(ipheader.Src.To4())
			iSockIP := binary.BigEndian.Uint32(sockaddr.Addr[:4])
			if iSrcIP != iSockIP {
				continue
			}
			err = tcpheader.Parse(rawbuf[14+ipheader.Len : buflen])
			if err != nil {
				log.Println(err)
				continue
			}

			if tcpheader.SPort == sockPort {
				ch <- TCPInfo{iDstIP, tcpheader.SeqNum, tcpheader.AckNum}
				break
			}
		}
	}()
	select {
	case res := <-ch:
		connInfo = res
	case <-time.After(time.Second * time.Duration(timeout)):
		syscall.Close(raw_fd)
		RAWIPMutex.Unlock()
		return syscall.ETIMEDOUT
	}
	syscall.Close(raw_fd)
	RAWIPMutex.Unlock()

	raw_fd, _ = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	var ipheader ipv4.Header
	var tcpheader tcp.Header
	ipheader.Version = 4
	ipheader.Len = 20
	ipheader.TOS = 0
	ipheader.TotalLen = 0
	ipheader.ID = 0
	ipheader.Flags = 2
	ipheader.FragOff = 0
	ipheader.TTL = ttl
	ipheader.Protocol = 6
	ipheader.Checksum = 0
	ipheader.Src = sockaddr.Addr[:4]
	ipheader.Dst = sa.(*syscall.SockaddrInet4).Addr[:4]
	ipheader.Options = nil

	tcpheader.SPort = sockPort
	tcpheader.DPort = uint16(sa.(*syscall.SockaddrInet4).Port)
	tcpheader.Offset = 5
	tcpheader.Flags = tcp.FlagPSH | tcp.FlagACK
	tcpheader.WinSize = 640
	tcpheader.UrgPointer = 0
	tcpheader.Options = nil
	//log.Println(ipheader)
	//log.Println(tcpheader)

	fakedata := make([]byte, len(data))
	ipheader.TotalLen = ipv4.HeaderLen + tcp.HeaderLen + len(data)
	psh := tcp.PseudoHeader{ipheader.Src, ipheader.Dst, 6, uint16(tcp.HeaderLen + len(data))}
	pshbyte, err := psh.Marshal()
	tcpheader.SeqNum = connInfo.SeqNum + 1
	tcpheader.AckNum = connInfo.AckNum
	tcpbyte, err := tcpheader.MarshalWithData(pshbyte, fakedata)
	ipbyte, _ := ipheader.Marshal()
	copy(rawbuf[:], ipbyte)
	copy(rawbuf[ipheader.Len:], tcpbyte)
	//time.Sleep(time.Millisecond * 20)
	err = syscall.Sendto(raw_fd, rawbuf[:ipheader.TotalLen], 0, sa)
	_, err = syscall.Write(fd, data[:hostOffset])
	err = syscall.Sendto(raw_fd, rawbuf[:ipheader.TotalLen], 0, sa)
	if err != nil {
		log.Println(host, err)
		syscall.Close(raw_fd)
		return err
	}
	//time.Sleep(time.Millisecond * 20)
	_, err = syscall.Write(fd, data[hostOffset:])
	if err != nil {
		log.Println(host, err)
		syscall.Close(raw_fd)
		return err
	}
	syscall.Close(raw_fd)
	return nil
}

func TTLSProxyHost(serverAddrList []net.TCPAddr, option string, client net.Conn, host string, port int, mss int) {
	defer client.Close()

	serverAddrCount := len(serverAddrList)
	if serverAddrCount == 0 {
		return
	}

	var server handle
	var err error
	var bindsa4 syscall.Sockaddr = nil
	var bindsa6 syscall.Sockaddr = nil

	data := make([]byte, 1460)
	n, err := client.Read(data)
	if err != nil {
		return
	}

	if MoveHttps(data[:n], client) {
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
	ttl := serverAddr.Port

	var sa syscall.Sockaddr
	ip4 := IP.To4()
	if ip4 != nil {
		var addr [4]byte
		copy(addr[:4], ip4[:4])
		sa = &syscall.SockaddrInet4{Addr: addr, Port: port}
		server, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
		if err != nil {
			log.Println(host, err)
		}
		if bindsa4 != nil {
			err = syscall.Bind(server, bindsa4)
			if err != nil {
				log.Println(host, err)
				return
			}
		}
	} else {
		var addr [16]byte
		copy(addr[:16], IP)
		sa = &syscall.SockaddrInet6{Addr: addr, Port: port}
		server, err = syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, 0)
	}
	defer syscall.Close(server)

	if mss > 0 {
		if SetTCPMaxSeg(server, mss) != nil {
			log.Println(err)
			return
		}
	}

	var bindsa syscall.Sockaddr
	if bindsa4 != nil {
		bindsa = bindsa4
	} else if bindsa6 != nil {
		bindsa = bindsa6
	}

	err = ConnectMaskS(server, data[:n], sa, ttl, host, bindsa, 2)

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
