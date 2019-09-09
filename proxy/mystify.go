// +build !windows

package proxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"

	//"sync"
	"syscall"
	"time"

	"../dns"
	"../net/ipv4"
	"../net/tcp"
)

type TCPInfo struct {
	Src    uint32
	Port   uint16
	TTL    uint16
	SeqNum uint32
	AckNum uint32
}

func htons(h uint16) uint16 {
	return ((h >> 8) & 0xFF) | ((h & 0xFF) << 8)
}

var PortChan [65536](chan TCPInfo)

func MystifyConnect(fd handle, sa syscall.Sockaddr, bindsa syscall.Sockaddr, timeout int) (TCPInfo, error) {
	raw_fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	defer syscall.Close(raw_fd)

	var connInfo = TCPInfo{0, 0, 0, 0, 0}

	if err != nil {
		log.Println(err)
		return connInfo, err
	}

	if bindsa != nil {
		err = syscall.Bind(raw_fd, bindsa)
		if err != nil {
			log.Println(err)
			return connInfo, err
		}
	}
	err = syscall.Connect(raw_fd, sa)
	if err != nil {
		log.Println(err)
		return connInfo, err
	}

	err = syscall.SetNonblock(fd, true)
	err = syscall.Connect(fd, sa)
	if err != syscall.EINPROGRESS {
		log.Println(err)
		return connInfo, err
	}

	var sockaddr *syscall.SockaddrInet4
	sockname, err := syscall.Getsockname(fd)
	if err != nil {
		log.Println(err)
		return connInfo, err
	}
	switch sockname.(type) {
	case *syscall.SockaddrInet4:
		sockaddr = sockname.(*syscall.SockaddrInet4)
	default:
		return connInfo, err
	}

	rawbuf := make([]byte, 1500)

	ch := make(chan TCPInfo)
	iSockIP := binary.BigEndian.Uint32(sockaddr.Addr[:4])
	sockPort := uint16(sockaddr.Port)
	PortChan[sockPort] = ch
	defer func() {
		PortChan[sockPort] = nil
	}()

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
				ch <- TCPInfo{iSockIP, sockPort, uint16(ipheader.TTL), tcpheader.AckNum, tcpheader.SeqNum + 1}
				break
			} else {
				pch := PortChan[tcpheader.DPort]
				if pch != nil {
					pch <- TCPInfo{iDstIP, tcpheader.DPort, uint16(ipheader.TTL), tcpheader.AckNum, tcpheader.SeqNum + 1}
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

const letterBytes = "0123456789abcdefghijklmnopqrstuvwxyz"

func RandStringBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return b
}

func MystifySend(fd handle, data []byte, sa syscall.Sockaddr, ttl int, host string, connInfo TCPInfo) error {
	var ipheader ipv4.Header
	var tcpheader tcp.Header
	var Src [4]byte
	binary.BigEndian.PutUint32(Src[:], connInfo.Src)
	sockPort := connInfo.Port

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
	ipheader.Src = Src[:4] //ipheader.Src = sockaddr.Addr[:4]
	ipheader.Dst = sa.(*syscall.SockaddrInet4).Addr[:4]
	ipheader.Options = nil

	tcpheader.SPort = uint16(sockPort)
	tcpheader.DPort = uint16(sa.(*syscall.SockaddrInet4).Port)
	tcpheader.Offset = 5
	tcpheader.Flags = tcp.FlagPSH | tcp.FlagACK
	tcpheader.WinSize = 640
	tcpheader.UrgPointer = 0
	tcpheader.Options = nil
	//log.Println(ipheader)
	//log.Println(tcpheader)

	rawbuf := make([]byte, 1500)
	fakedata := make([]byte, len(data))

	hostbyte := []byte(host)
	if len(host) > 0 {
		copy(fakedata[:], data)
		fakedata = bytes.Replace(fakedata, hostbyte, RandStringBytes(len(hostbyte)), 1)
	}

	ipheader.TotalLen = ipv4.HeaderLen + tcp.HeaderLen + len(data)
	psh := tcp.PseudoHeader{ipheader.Src, ipheader.Dst, 6, uint16(tcp.HeaderLen + len(data))}
	pshbyte, err := psh.Marshal()
	tcpheader.SeqNum = connInfo.SeqNum
	tcpheader.AckNum = connInfo.AckNum
	tcpbyte, err := tcpheader.MarshalWithData(pshbyte, fakedata)
	ipbyte, _ := ipheader.Marshal()
	copy(rawbuf[:], ipbyte)
	copy(rawbuf[ipheader.Len:], tcpbyte)
	//time.Sleep(time.Millisecond * 20)

	raw_fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	defer syscall.Close(raw_fd)
	err = syscall.Sendto(raw_fd, rawbuf[:ipheader.TotalLen], 0, sa)
	if err != nil {
		log.Println(host, err)
		return err
	}

	time.Sleep(10 * time.Millisecond)

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
			if len(hostbyte)/2 < 8 {
				hostOffset -= len(hostbyte) / 2
			} else {
				hostOffset -= 8
			}

			_, err = syscall.Write(fd, data[:hostOffset])
			if err != nil {
				return err
			}

			err = syscall.Sendto(raw_fd, rawbuf[:ipheader.TotalLen], 0, sa)
			if err != nil {
				log.Println(host, err)
				return err
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	_, err = syscall.Write(fd, data[hostOffset:])
	if err != nil {
		log.Println(host, err, sa)
		return err
	}
	return nil
}

func MystifyHead(fd handle, sa syscall.Sockaddr, ttl int, connInfo TCPInfo) error {
	var ipheader ipv4.Header
	var tcpheader tcp.Header
	var Src [4]byte
	binary.BigEndian.PutUint32(Src[:], connInfo.Src)
	sockPort := connInfo.Port

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
	ipheader.Src = Src[:4]
	ipheader.Dst = sa.(*syscall.SockaddrInet4).Addr[:4]
	ipheader.Options = nil

	tcpheader.SPort = uint16(sockPort)
	tcpheader.DPort = uint16(sa.(*syscall.SockaddrInet4).Port)
	tcpheader.Offset = 5
	tcpheader.Flags = tcp.FlagPSH | tcp.FlagACK
	tcpheader.WinSize = 640
	tcpheader.UrgPointer = 0
	tcpheader.Options = nil

	rawbuf := make([]byte, 1500)
	fakedata := make([]byte, 1400)

	ipheader.TotalLen = ipv4.HeaderLen + tcp.HeaderLen + len(fakedata)
	psh := tcp.PseudoHeader{ipheader.Src, ipheader.Dst, 6, uint16(tcp.HeaderLen + len(fakedata))}
	pshbyte, err := psh.Marshal()
	tcpheader.SeqNum = connInfo.SeqNum
	tcpheader.AckNum = connInfo.AckNum
	tcpbyte, err := tcpheader.MarshalWithData(pshbyte, fakedata)
	ipbyte, _ := ipheader.Marshal()
	copy(rawbuf[:], ipbyte)
	copy(rawbuf[ipheader.Len:], tcpbyte)

	raw_fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	defer syscall.Close(raw_fd)
	err = syscall.Sendto(raw_fd, rawbuf[:ipheader.TotalLen], 0, sa)
	if err != nil {
		log.Println(err)
		return err
	}

	time.Sleep(5 * time.Millisecond)

	err = syscall.Sendto(raw_fd, rawbuf[:ipheader.TotalLen], 0, sa)
	if err != nil {
		log.Println(err)
		return err
	}

	time.Sleep(5 * time.Millisecond)

	return nil
}

//var DstMutex sync.RWMutex
//var DstMutexMap map[string]*sync.Mutex = make(map[string]*sync.Mutex)

func MystifyProxy(serverAddrList []AddrInfo, option string, client net.Conn, host string, port int, ttl int, mss int, headdata []byte) {
	defer client.Close()

	serverAddrCount := len(serverAddrList)
	if serverAddrCount == 0 {
		return
	}

	var server handle
	var err error
	var connInfo TCPInfo
	var sa syscall.Sockaddr
	var serverAddr net.TCPAddr

	for i := 0; i < 3; i++ {
		addressInfo := serverAddrList[rand.Intn(serverAddrCount)]

		var iface string
		if len(addressInfo.Interface) == 0 {
			ifaces := strings.Split(option, "|")
			iface = ifaces[rand.Intn(len(ifaces))]
		} else {
			iface = addressInfo.Interface
		}

		serverAddr = addressInfo.Address
		IP := serverAddr.IP

		ip4 := IP.To4()
		if ip4 == nil {
			log.Println(IP, "Not IPv4")
			return
		}
		var addr [4]byte
		copy(addr[:4], ip4[:4])
		sa = &syscall.SockaddrInet4{Addr: addr, Port: port}
		server, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
		if err != nil {
			log.Println(host, err)
			continue
		}

		bindsa, err := BindInterface(server, iface)
		if err != nil {
			log.Println(host, iface, err)
			syscall.Close(server)
			continue
		}

		if mss > 87 {
			err = SetTCPMaxSeg(server, mss)
			if err != nil {
				log.Println(err)
				syscall.Close(server)
				continue
			}
		}

		connInfo, err = MystifyConnect(server, sa, bindsa, 3)
		if err != nil {
			log.Println(host, err)
			syscall.Close(server)
			continue
		}
	}
	if err != nil {
		return
	}
	defer syscall.Close(server)

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

	if mss > 0 {
		err = MystifySend(server, data[:n], sa, ttl, host, connInfo)
	} else {
		err = MystifySend(server, data[:n], sa, ttl, "", connInfo)
	}

	if err != nil {
		log.Println(host, serverAddr, err)
		return
	}

	if SetTCPKeepAlive(server, true) != nil {
		log.Println(err)
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
			return
		}

		client.SetReadDeadline(time.Now().Add(CONN_TTL))

		n, err = SendAll(server, data[:n])
		if err != nil {
			return
		}
	}
}

func MystifyHTTP(serverAddrList []AddrInfo, option string, client net.Conn, host string, port int, ttl int, mss int) {
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
	ip4 := IP.To4()
	if ip4 == nil {
		log.Println(IP, "Not IPv4")
		return
	}
	var addr [4]byte
	copy(addr[:4], ip4[:4])
	sa = &syscall.SockaddrInet4{Addr: addr, Port: port}
	server, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		log.Println(host, err)
	}

	bindsa, err := BindInterface(server, iface)
	if bindsa == nil || err != nil {
		log.Println(host, err)
		return
	}

	defer syscall.Close(server)

	if mss > 0 {
		err = SetTCPMaxSeg(server, mss)
		if err != nil {
			log.Println(err)
			return
		}
	}

	var connInfo TCPInfo
	connInfo, err = MystifyConnect(server, sa, bindsa, 10)

	data := make([]byte, 1460)

	go ForwardFromSocket(server, client)
	for {
		n, err := client.Read(data)
		if LogEnable && err != nil {
			log.Println(n, err)
		}
		if n <= 0 {
			return
		}
		client.SetReadDeadline(time.Now().Add(CONN_TTL))

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

		if mss > 512 {
			err = MystifySend(server, []byte(request), sa, ttl, "", connInfo)
		} else {
			err = MystifySend(server, []byte(request), sa, ttl, host, connInfo)
		}

		connInfo.SeqNum += uint32(len(request))
		if err != nil {
			return
		}
	}
}

func MystifyTCPLookup(request []byte, address string, ttl int) ([]byte, error) {
	serverAddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, err
	}

	var sa syscall.Sockaddr
	ip4 := serverAddr.IP.To4()
	if ip4 == nil {
		log.Println(serverAddr.IP, "Not IPv4")
		return nil, err
	}
	var addr [4]byte
	copy(addr[:4], ip4[:4])
	sa = &syscall.SockaddrInet4{Addr: addr, Port: serverAddr.Port}
	server, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		log.Println(address, err)
	}
	defer syscall.Close(server)

	var connInfo TCPInfo
	connInfo, err = MystifyConnect(server, sa, nil, 10)

	data := make([]byte, 4096)
	binary.BigEndian.PutUint16(data[:2], uint16(len(request)))
	copy(data[2:], request)

	err = MystifySend(server, data[:len(request)+2], sa, ttl, "", connInfo)
	if err != nil {
		return nil, err
	}

	length := 0
	recvlen := 0
	for {
		n, err := syscall.Read(server, data[length:])
		if err != nil {
			return nil, err
		}

		if length == 0 {
			length = int(binary.BigEndian.Uint16(data[:2]) + 2)
			if length > 4096 {
				return nil, errors.New("Invalid Length")
			}
		}
		recvlen += n
		if recvlen >= length {
			return data[2:recvlen], nil
		}
	}

	return nil, nil
}

func MystifyHTTPProxy(serverAddrList []AddrInfo, option string, client net.Conn, host string, port int, ttl int, mss int, headdata []byte) {
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
	ip4 := IP.To4()
	if ip4 == nil {
		log.Println(IP, "Not IPv4")
		return
	}
	var addr [4]byte
	copy(addr[:4], ip4[:4])
	sa = &syscall.SockaddrInet4{Addr: addr, Port: serverAddr.Port}
	server, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		log.Println(host, err)
	}
	defer syscall.Close(server)

	bindsa, err := BindInterface(server, iface)
	if err != nil {
		log.Println(host, iface, err)
		return
	}

	if mss > 87 {
		err = SetTCPMaxSeg(server, mss)
		if err != nil {
			log.Println(err)
			return
		}
	}

	var connInfo TCPInfo

	connInfo, err = MystifyConnect(server, sa, bindsa, 6)
	if err != nil {
		log.Println(host, err)
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

	head := []byte("CONNECT " + host + ":" + strconv.Itoa(port) + " HTTP/1.1\r\n\r\n")
	if mss > 0 {
		err = MystifySend(server, head, sa, ttl, "", connInfo)
	} else {
		err = MystifySend(server, head, sa, ttl, host, connInfo)
	}
	if err != nil {
		log.Println(host, serverAddr, err)
		return
	} else {
		b := make([]byte, 512)
		n, err := syscall.Read(server, b[:])
		if err != nil {
			log.Println(host, serverAddr, err)
			return
		}

		if string(b[:13]) != "HTTP/1.1 200 " {
			log.Println(serverAddr, strings.Split(string(b[:n]), "\r\n")[0])
			return
		}

		connInfo.SeqNum += uint32(len(head))
		connInfo.AckNum += uint32(n)
	}

	if mss > 0 {
		err = MystifySend(server, data[:n], sa, ttl, host, connInfo)
	} else {
		err = MystifySend(server, data[:n], sa, ttl, "", connInfo)
	}

	if err != nil {
		log.Println(host, serverAddr, err)
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
			return
		}
		client.SetReadDeadline(time.Now().Add(CONN_TTL))

		n, err = SendAll(server, data[:n])
		if err != nil {
			return
		}
	}
}

func MystifySocksProxy(serverAddrList []AddrInfo, option string, client net.Conn, host string, port int, ttl int, mss int, headdata []byte) {
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
	ip4 := IP.To4()
	if ip4 == nil {
		log.Println(IP, "Not IPv4")
		return
	}
	var addr [4]byte
	copy(addr[:4], ip4[:4])
	sa = &syscall.SockaddrInet4{Addr: addr, Port: serverAddr.Port}
	server, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		log.Println(host, err)
	}
	defer syscall.Close(server)

	bindsa, err := BindInterface(server, iface)
	if err != nil {
		log.Println(host, iface, err)
		return
	}

	if mss > 87 {
		err = SetTCPMaxSeg(server, mss)
		if err != nil {
			log.Println(err)
			return
		}
	}

	var connInfo TCPInfo

	connInfo, err = MystifyConnect(server, sa, bindsa, 6)
	if err != nil {
		log.Println(host, err)
		return
	}

	err = MystifyHead(server, sa, ttl, connInfo)
	if err != nil {
		log.Println(host, serverAddr, err)
		return
	}

	data := make([]byte, 1460)

	_, err = syscall.Write(server, []byte{0x05, 0x01, 0x00})
	if err != nil {
		log.Println(host, serverAddr, err)
		return
	}

	n, err := syscall.Read(server, data)
	if err != nil {
		log.Println(host, serverAddr, err)
		return
	}

	if data[0] == 0x05 {
		copy(data[:], []byte{0x05, 0x01, 0x00, 0x03})
		bHost := []byte(host)
		hostLen := len(bHost)
		data[4] = byte(hostLen)
		copy(data[5:], bHost)
		binary.BigEndian.PutUint16(data[5+hostLen:], uint16(port))
		_, err = syscall.Write(server, data[:7+hostLen])
		if err != nil {
			log.Println(err)
			return
		}
		n, err := syscall.Read(server, data[:])
		if err != nil {
			log.Println(err)
			return
		}
		if n < 2 {
			return
		}
		if data[0] != 0x05 {
			log.Println("VER:", data[0])
			return
		}
		if data[1] != 0x00 {
			log.Println("REP:", data[1])
			return
		}
	}

	go ForwardFromSocket(server, client)

	n = 0
	if len(headdata) > 0 {
		copy(data[:], headdata[:])
		n = len(headdata)
	} else {
		n, err = client.Read(data)
		if err != nil {
			return
		}
	}

	n, err = SendAll(server, data[:n])
	if err != nil {
		return
	}

	for {
		n, err := client.Read(data)
		if LogEnable && err != nil {
			log.Println(n, err)
		}
		if n <= 0 {
			return
		}

		client.SetReadDeadline(time.Now().Add(CONN_TTL))

		n, err = SendAll(server, data[:n])
		if err != nil {
			return
		}
	}
}

func MystifySocksProxyAddr(serverAddrList []AddrInfo, option string, client net.Conn, address *net.TCPAddr, ttl int, mss int, headdata []byte) {
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
	ip4 := IP.To4()
	if ip4 == nil {
		log.Println(IP, "Not IPv4")
		return
	}
	var addr [4]byte
	copy(addr[:4], ip4[:4])
	sa = &syscall.SockaddrInet4{Addr: addr, Port: serverAddr.Port}
	server, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		log.Println(address, err)
	}
	defer syscall.Close(server)

	bindsa, err := BindInterface(server, iface)
	if err != nil {
		log.Println(address, iface, err)
		return
	}

	if mss > 87 {
		err = SetTCPMaxSeg(server, mss)
		if err != nil {
			log.Println(err)
			return
		}
	}

	var connInfo TCPInfo

	connInfo, err = MystifyConnect(server, sa, bindsa, 6)
	if err != nil {
		log.Println(address, err)
		return
	}

	err = MystifyHead(server, sa, ttl, connInfo)
	if err != nil {
		log.Println(address, serverAddr, err)
		return
	}

	data := make([]byte, 1460)

	_, err = syscall.Write(server, []byte{0x05, 0x01, 0x00})
	if err != nil {
		log.Println(address, serverAddr, err)
		return
	}

	n, err := syscall.Read(server, data)
	if err != nil {
		log.Println(address, serverAddr, err)
		return
	}

	if data[0] == 0x05 {
		IP := []byte(address.IP)
		headLen := 4
		if len(IP) == 4 {
			copy(data[:], []byte{0x05, 0x01, 0x00, 0x01})
			copy(data[4:], IP)
			headLen += 4
		} else {
			copy(data[:], []byte{0x05, 0x01, 0x00, 0x04})
			copy(data[4:], IP)
			headLen += 16
		}
		binary.BigEndian.PutUint16(data[headLen:], uint16(address.Port))
		headLen += 2
		_, err = syscall.Write(server, data[:headLen])
		if err != nil {
			log.Println(err)
			return
		}
		n, err := syscall.Read(server, data[:])
		if err != nil {
			log.Println(err)
			return
		}
		if n < 2 {
			return
		}
		if data[0] != 0x05 {
			log.Println("VER:", data[0])
			return
		}
		if data[1] != 0x00 {
			log.Println("REP:", data[1])
			return
		}
	}

	go ForwardFromSocket(server, client)

	n = 0
	if len(headdata) > 0 {
		copy(data[:], headdata[:])
		n = len(headdata)
	} else {
		n, err = client.Read(data)
		if err != nil {
			return
		}
	}

	n, err = SendAll(server, data[:n])
	if err != nil {
		return
	}

	for {
		n, err := client.Read(data)
		if LogEnable && err != nil {
			log.Println(n, err)
		}
		if n <= 0 {
			return
		}

		client.SetReadDeadline(time.Now().Add(CONN_TTL))

		n, err = SendAll(server, data[:n])
		if err != nil {
			return
		}
	}
}

func MystifySocks4aProxy(serverAddrList []AddrInfo, option string, client net.Conn, host string, port int, ttl int, mss int, headdata []byte) {
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
	ip4 := IP.To4()
	if ip4 == nil {
		log.Println(IP, "Not IPv4")
		return
	}
	var addr [4]byte
	copy(addr[:4], ip4[:4])
	sa = &syscall.SockaddrInet4{Addr: addr, Port: serverAddr.Port}
	server, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		log.Println(host, err)
	}
	defer syscall.Close(server)

	bindsa, err := BindInterface(server, iface)
	if err != nil {
		log.Println(host, iface, err)
		return
	}

	if mss > 87 {
		err = SetTCPMaxSeg(server, mss)
		if err != nil {
			log.Println(err)
			return
		}
	}

	var connInfo TCPInfo

	connInfo, err = MystifyConnect(server, sa, bindsa, 6)
	if err != nil {
		log.Println(host, err)
		return
	}

	data := make([]byte, 1460)
	copy(data[:], []byte{0x04, 0x01})
	binary.BigEndian.PutUint16(data[2:], uint16(port))
	binary.BigEndian.PutUint32(data[4:], 1)
	data[8] = 0x00
	bHost := []byte(host)
	copy(data[9:], bHost)
	headLen := 9 + len(bHost)
	data[headLen] = 0x00
	headLen++

	err = MystifySend(server, data[:headLen], sa, ttl, "", connInfo)
	if err != nil {
		log.Println(host, serverAddr, err)
		return
	}
	connInfo.SeqNum += uint32(headLen)

	n, err := syscall.Read(server, data[:])
	if err != nil {
		log.Println(err)
		return
	}
	if n < 8 {
		log.Println(serverAddr, "Proxy Closed")
		return
	}
	if data[0] != 0 {
		log.Println("VER:", data[0])
		return
	}
	if data[1] != 90 {
		log.Println("REP:", data[1])
		return
	}

	connInfo.AckNum += uint32(n)

	go ForwardFromSocket(server, client)

	n = 0
	if len(headdata) > 0 {
		copy(data[:], headdata[:])
		n = len(headdata)
	} else {
		n, err = client.Read(data)
		if err != nil {
			return
		}
	}

	err = MystifySend(server, data[:n], sa, ttl, host, connInfo)
	if err != nil {
		return
	}

	for {
		n, err := client.Read(data)
		if LogEnable && err != nil {
			log.Println(n, err)
		}
		if n <= 0 {
			return
		}

		client.SetReadDeadline(time.Now().Add(CONN_TTL))

		n, err = SendAll(server, data[:n])
		if err != nil {
			return
		}
	}
}

func CreatSocks4Conn(serverAddr net.TCPAddr, iface string, address *net.TCPAddr, ttl int, mss int, headdata []byte, host string) (handle, error) {
	IP := serverAddr.IP

	var sa syscall.Sockaddr
	var server handle

	ip4 := IP.To4()
	if ip4 == nil {
		return 0, errors.New("Not IPv4")
	}
	var addr [4]byte
	copy(addr[:4], ip4[:4])
	sa = &syscall.SockaddrInet4{Addr: addr, Port: serverAddr.Port}
	server, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		log.Println(address, err)
		syscall.Close(server)
		return 0, err
	}

	bindsa, err := BindInterface(server, iface)
	if err != nil {
		log.Println(address, iface, err)
		syscall.Close(server)
		return 0, err
	}

	if mss > 87 {
		err = SetTCPMaxSeg(server, mss)
		if err != nil {
			log.Println(err)
			syscall.Close(server)
			return 0, err
		}
	}

	var connInfo TCPInfo

	connInfo, err = MystifyConnect(server, sa, bindsa, 6)
	if err != nil {
		log.Println(address, err)
		syscall.Close(server)
		return 0, err
	}

	data := make([]byte, 1460)

	ipv4 := address.IP.To4()
	if ipv4 == nil {
		syscall.Close(server)
		return 0, errors.New("Not IPv4")
	}
	IP = []byte(ipv4)
	copy(data[:], []byte{0x04, 0x01})
	binary.BigEndian.PutUint16(data[2:], uint16(address.Port))
	copy(data[4:], IP)
	data[8] = 0x00

	err = MystifySend(server, data[:9], sa, ttl, "", connInfo)
	if err != nil {
		log.Println(err)
		syscall.Close(server)
		return 0, err
	}

	n, err := syscall.Read(server, data[:])
	if err != nil {
		log.Println(err)
		syscall.Close(server)
		return 0, err
	}
	if n == 0 {
		syscall.Close(server)
		return 0, errors.New("Proxy Closed")
	}
	if n < 8 {
		syscall.Close(server)
		return 0, errors.New("Responsce Too Short")
	}
	if data[0] != 0 {
		syscall.Close(server)
		return 0, errors.New("Proxy Error")
	}
	if data[1] != 90 {
		syscall.Close(server)
		return 0, errors.New("Proxy Not Allow")
	}

	connInfo.SeqNum += 9
	connInfo.AckNum += uint32(n)
	if len(headdata) > 0 {
		err = MystifySend(server, headdata, sa, ttl, host, connInfo)
		if err != nil {
			syscall.Close(server)
			return 0, err
		}
	}

	return server, nil
}

func MystifySocks4ProxyAddr(serverAddrList []AddrInfo, option string, client net.Conn, address *net.TCPAddr, ttl int, mss int, headdata []byte) {
	defer client.Close()

	serverAddrCount := len(serverAddrList)
	if serverAddrCount == 0 {
		return
	}

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
	server, err := CreatSocks4Conn(serverAddr, iface, address, ttl, mss, nil, "")
	if err != nil {
		log.Println(serverAddr, err)
		return
	}
	defer syscall.Close(server)

	go ForwardFromSocket(server, client)

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

	n, err = SendAll(server, data[:n])
	if err != nil {
		return
	}

	for {
		n, err := client.Read(data)
		if LogEnable && err != nil {
			log.Println(n, err)
		}
		if n <= 0 {
			return
		}

		client.SetReadDeadline(time.Now().Add(CONN_TTL))

		n, err = SendAll(server, data[:n])
		if err != nil {
			return
		}
	}
}

func MystifySocks4Proxy(serverAddrList []AddrInfo, option string, client net.Conn, host string, port int, ttl int, mss int, headdata []byte) {
	defer client.Close()

	serverAddrCount := len(serverAddrList)
	if serverAddrCount == 0 {
		return
	}

	addressInfo := serverAddrList[rand.Intn(serverAddrCount)]

	var iface string
	if len(addressInfo.Interface) == 0 {
		ifaces := strings.Split(option, "|")
		iface = ifaces[rand.Intn(len(ifaces))]
	} else {
		iface = addressInfo.Interface
	}

	serverAddr := addressInfo.Address

	HostMapMutex.Lock()
	var IPList []net.TCPAddr = nil
	if ProxyHostMap != nil {
		IPList, _ = ProxyHostMap[host]
	} else {
		ProxyHostMap = make(map[string][]net.TCPAddr)
	}
	HostMapMutex.Unlock()

	data := make([]byte, 4096)

	if len(IPList) == 0 {
		/*
			var header dns.Header
			header.ID = 0
			header.Flag = 0x0100
			header.QDCount = 1
			header.ANCount = 0
			header.NSCount = 0
			header.ARCount = 0

			var question dns.Question
			question.QName = host
			question.QType = 0x01
			question.QClass = 0x01

			request := dns.PackRequest(header, question)

			//DNS over TCP
			binary.BigEndian.PutUint16(data[:2], uint16(len(request)))
			copy(data[2:], request)

			address, _ := net.ResolveTCPAddr("tcp", "8.8.8.8:53")
			nsconn, err := CreatSocks4Conn(serverAddr, iface, address, ttl, mss, data[:len(request)+2], "")
			if err != nil {
				log.Println(serverAddr, err)
				return
			}

			length := 0
			recvlen := 0
			for {
				n, err := syscall.Read(nsconn, data[length:])
				if err != nil {
					log.Println(err)
					syscall.Close(nsconn)
					return
				}
				if length == 0 {
					length = int(binary.BigEndian.Uint16(data[:2]) + 2)
				}
				recvlen += n
				if recvlen >= length {
					syscall.Close(nsconn)
					break
				}
			}
			response := data[2:recvlen]

			rheader, offset := dns.UnpackHeader(response)
			question, off, _ := dns.UnpackQuestion(response[offset:])
			offset += off
			IPList = dns.UnPackAnswers(response[offset:], int(rheader.ANCount))
			HostMapMutex.Lock()
			ProxyHostMap[host] = IPList
			HostMapMutex.Unlock()
			if LogEnable {
				log.Println(host, ":", IPList)
			}
		*/
		var err error
		url := "https://dns.google.com/resolve?name=[NAME]&type=A&edns_client_subnet=" + serverAddr.IP.String()
		IPList, err = dns.HTTPSLookup(host, dns.TypeA, url)
		if err != nil {
			log.Println(err)
			return
		}
		HostMapMutex.Lock()
		ProxyHostMap[host] = IPList
		HostMapMutex.Unlock()
		if LogEnable {
			log.Println(host, ":", IPList)
		}
	}

	if len(IPList) == 0 {
		if LogEnable {
			log.Println(host, "NOIP")
		}
		return
	}

	n := 0
	var err error
	if len(headdata) > 0 {
		copy(data[:], headdata[:])
		n = len(headdata)
	} else {
		n, err = client.Read(data)
		if err != nil {
			return
		}
	}

	var address net.TCPAddr
	address.IP = IPList[rand.Intn(len(IPList))].IP
	address.Port = port

	server, err := CreatSocks4Conn(serverAddr, iface, &address, ttl, mss, data[:n], host)
	if err != nil {
		log.Println(serverAddr, err)
		return
	}
	defer syscall.Close(server)

	go ForwardFromSocket(server, client)
	for {
		n, err := client.Read(data)
		if LogEnable && err != nil {
			log.Println(n, err)
		}
		if n <= 0 {
			return
		}

		client.SetReadDeadline(time.Now().Add(CONN_TTL))

		n, err = SendAll(server, data[:n])
		if err != nil {
			return
		}
	}
}
