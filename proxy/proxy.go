// +build !windows

package proxy

import (
	"encoding/binary"
	"math/rand"
	"net"
	"syscall"
)

const (
	Direct  = 0x00
	HTTP    = 0x02
	HTTPS   = 0x03
	IPv6to4 = 0x04
	Socks5  = 0x05
	IPv4to6 = 0x06

	MOVE    = 0x07
	MOVETFO = 0x08
	BIND    = 0x09
	BINDTFO = 0x0A
	TTL     = 0x0B
	TTLS    = 0x0C
	TFO     = 0x0D
)

const BUFFER_SIZE int = 65536

const SOL_TCP = syscall.SOL_TCP

type handle = int

type ProxyInfo struct {
	Type     uint16
	MSS      uint16
	AddrList []net.TCPAddr
	Option   string
}

func SendAll(sock int, data []byte) (int, error) {
	length := len(data)
	sended := 0
	for {
		n, err := syscall.Write(sock, data[sended:])
		if n <= 0 {
			return n, err
		}
		sended += n
		if sended == length {
			break
		}
	}
	return sended, nil
}

func Forward(src net.Conn, dst net.Conn) {
	data := make([]byte, BUFFER_SIZE)
	defer src.Close()
	defer dst.Close()
	for {
		n, _ := src.Read(data)
		if n <= 0 {
			return
		}
		length := n
		sended := 0
		for {
			n, _ := dst.Write(data[sended:length])
			if n <= 0 {
				return
			}
			sended += n
			if sended == length {
				break
			}
		}
	}
}

func ForwardFromSocket(src int, dst net.Conn) {
	data := make([]byte, BUFFER_SIZE)
	defer syscall.Close(src)
	defer dst.Close()
	for {
		n, _ := syscall.Read(src, data)
		if n <= 0 {
			return
		}
		length := n
		sended := 0
		for {
			n, _ := dst.Write(data[sended:length])
			if n <= 0 {
				return
			}
			sended += n
			if sended == length {
				break
			}
		}
	}
}

func DialEx(host string, data []byte) (handle, error) {
	remoteAddr, err := net.ResolveTCPAddr("tcp", host)
	if err != nil {
		return 0, err
	}
	IP := remoteAddr.IP
	var remote handle
	var sa syscall.Sockaddr

	ip4 := IP.To4()
	if ip4 != nil {
		var addr [4]byte
		copy(addr[:4], ip4)
		sa = &syscall.SockaddrInet4{Addr: addr, Port: remoteAddr.Port}
		remote, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	} else {
		var addr [16]byte
		copy(addr[:16], IP)
		sa = &syscall.SockaddrInet6{Addr: addr, Port: remoteAddr.Port}
		remote, err = syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, 0)
	}
	if err != nil {
		return 0, err
	}
	err = syscall.Sendto(remote, data[:], syscall.MSG_FASTOPEN, sa)
	if err != nil {
		return 0, err
	}
	err = syscall.SetsockoptInt(remote, syscall.SOL_TCP, syscall.TCP_NODELAY, 1)
	return remote, err
}

func ConnectEx(fd handle, p []byte, to syscall.Sockaddr) error {
	err := syscall.Sendto(fd, p, syscall.MSG_FASTOPEN, to)
	if err != nil {
		return err
	}
	err = syscall.SetsockoptInt(fd, syscall.SOL_TCP, syscall.TCP_NODELAY, 1)
	return err
}

func Connect(fd handle, to syscall.Sockaddr) error {
	err := syscall.Connect(fd, to)
	if err != nil {
		return err
	}
	err = syscall.SetsockoptInt(fd, syscall.SOL_TCP, syscall.TCP_NODELAY, 1)
	return err
}

func SetTCPMaxSeg(fd handle, mss int) error {
	return syscall.SetsockoptInt(fd, syscall.SOL_TCP, syscall.TCP_MAXSEG, mss)
}

func SetTCPKeepAlive(fd handle, keep bool) error {
	if keep {
		err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)
		err = syscall.SetsockoptInt(fd, syscall.SOL_TCP, syscall.TCP_KEEPIDLE, 30)
		err = syscall.SetsockoptInt(fd, syscall.SOL_TCP, syscall.TCP_KEEPINTVL, 2)
		err = syscall.SetsockoptInt(fd, syscall.SOL_TCP, syscall.TCP_KEEPCNT, 3)
		return err
	} else {
		return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 0)
	}
}

const (
	SO_ORIGINAL_DST      = 80
	IP6T_SO_ORIGINAL_DST = 80
)

func GetOriginalDST(conn *net.TCPConn) (*net.TCPAddr, error) {
	file, err := conn.File()
	if err != nil {
		return nil, err
	}
	defer file.Close()

	LocalAddr := conn.LocalAddr()
	LocalTCPAddr, err := net.ResolveTCPAddr(LocalAddr.Network(), LocalAddr.String())

	if LocalTCPAddr.IP.To4() == nil {
		mtuinfo, err := syscall.GetsockoptIPv6MTUInfo(int(file.Fd()), syscall.IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST)
		if err != nil {
			return nil, err
		}

		raw := mtuinfo.Addr
		var ip net.IP = raw.Addr[:]

		port := int(raw.Port&0xFF)<<8 | int(raw.Port&0xFF00)>>8
		TCPAddr := net.TCPAddr{ip, port, ""}

		return &TCPAddr, nil
	} else {
		raw, err := syscall.GetsockoptIPv6Mreq(int(file.Fd()), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
		if err != nil {
			return nil, err
		}

		var ip net.IP = raw.Multiaddr[4:8]
		port := int(raw.Multiaddr[2])<<8 | int(raw.Multiaddr[3])
		TCPAddr := net.TCPAddr{ip, port, ""}

		if TCPAddr.IP.Equal(LocalTCPAddr.IP) {
			return nil, nil
		}

		return &TCPAddr, nil
	}

	return nil, nil
}

func Proxy(client net.Conn, address string) error {
	server, err := net.Dial("tcp", address)
	if err != nil {
		return err
	}
	defer server.Close()
	go Forward(server, client)
	Forward(client, server)

	return nil
}

func ProxyTFO(client net.Conn, address string) error {
	var data [2048]byte
	n, err := client.Read(data[:])
	if n <= 0 {
		return err
	}
	server, err := DialEx(address, data[:n])
	defer syscall.Close(server)
	if err != nil {
		return err
	}
	go ForwardFromSocket(server, client)
	for {
		n, err := client.Read(data[:])
		if n <= 0 {
			return nil
		}
		n, err = SendAll(server, data[:n])
		if err != nil {
			return nil
		}
	}
}

func ProxyAddress(client net.Conn, serverAddrList []net.TCPAddr, port int) error {
	serverAddrCount := len(serverAddrList)
	if serverAddrCount == 0 {
		return nil
	}
	serverAddr := serverAddrList[rand.Intn(serverAddrCount)]
	serverAddr.Port = port

	server, err := net.DialTCP("tcp", nil, &serverAddr)
	if err != nil {
		return err
	}
	defer server.Close()

	go Forward(server, client)
	Forward(client, server)

	return nil
}

func GetSNI(b []byte) string {
	//Version := binary.LittleEndian.Uint16(b[1:3])
	Length := binary.BigEndian.Uint16(b[3:5])
	if len(b) <= int(Length)-5 {
		return ""
	}
	//HandshakeType := b[5]
	//HandshakeLength := binary.LittleEndian.Uint16(b[7:9])
	//HandshakeVersion := binary.LittleEndian.Uint16(b[9:11])
	offset := 11 + 32
	SessionIDLength := b[offset]
	offset += 1 + int(SessionIDLength)
	CipherSuitersLength := binary.BigEndian.Uint16(b[offset : offset+2])
	offset += 2 + int(CipherSuitersLength)
	if offset >= len(b) {
		return ""
	}
	CompressionMethodsLenght := b[offset]
	offset += 1 + int(CompressionMethodsLenght)
	ExtensionsLength := binary.BigEndian.Uint16(b[offset : offset+2])
	offset += 2
	ExtensionsEnd := offset + int(ExtensionsLength)
	for offset < ExtensionsEnd {
		ExtensionType := binary.BigEndian.Uint16(b[offset : offset+2])
		offset += 2
		ExtensionLength := binary.BigEndian.Uint16(b[offset : offset+2])
		offset += 2
		if ExtensionType == 0 {
			//ServerNameListLength := binary.LittleEndian.Uint16(b[offset : offset+2])
			offset += 2
			//ServerNameType := b[offset]
			offset++
			ServerNameLength := binary.BigEndian.Uint16(b[offset : offset+2])
			offset += 2
			return string(b[offset:ServerNameLength])
		} else {
			offset += int(ExtensionLength)
		}
	}
	return ""
}
