// +build !windows

package proxy

import (
	"bytes"
	"encoding/binary"
	"log"
	"math/rand"
	"net"
	"strings"

	//"sync"
	"syscall"
	"time"

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
			err = syscall.Sendto(raw_fd, rawbuf[:ipheader.TotalLen], 0, sa)
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
		if n <= 0 {
			return
		}
		n, err = SendAll(server, data[:n])
		if err != nil {
			return
		}
	}
}

func MystifyProxyHTTP(serverAddrList []AddrInfo, option string, client net.Conn, host string, port int, ttl int, mss int) {
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

		err = MystifySend(server, []byte(request), sa, ttl, host, connInfo)
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
		}
		recvlen += n
		if recvlen >= length {
			return data[2:recvlen], nil
		}
	}

	return nil, nil
}
