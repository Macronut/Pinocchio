package proxy

import (
	"encoding/binary"
	"log"
	"math/rand"
	"net"
	"syscall"
	"unsafe"
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

const (
	TCP_NODELAY              = 0x0001
	TCP_EXPEDITED_1122       = 0x0002
	TCP_KEEPALIVE            = 3
	TCP_MAXSEG               = 4
	TCP_MAXRT                = 5
	TCP_STDURG               = 6
	TCP_NOURG                = 7
	TCP_ATMARK               = 8
	TCP_NOSYNRETRIES         = 9
	TCP_TIMESTAMPS           = 10
	TCP_OFFLOAD_PREFERENCE   = 11
	TCP_CONGESTION_ALGORITHM = 12
	TCP_DELAY_FIN_ACK        = 13
	TCP_MAXRTMS              = 14
	TCP_FASTOPEN             = 15
	TCP_KEEPCNT              = 16
	TCP_KEEPIDLE             = TCP_KEEPALIVE
	TCP_KEEPINTVL            = 17
)

const BUFFER_SIZE int = 65536

const SOL_TCP = syscall.IPPROTO_TCP

type handle = syscall.Handle

type ProxyInfo struct {
	Type     uint16
	MSS      uint16
	AddrList []net.TCPAddr
	Option   string
}

func SendAll(sock handle, data []byte) (int, error) {
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

func ForwardFromSocket(src handle, dst net.Conn) {
	data := make([]byte, BUFFER_SIZE)
	defer syscall.Close(src)
	defer dst.Close()
	for {
		n, err := syscall.Read(src, data)
		if err != nil {
			log.Println(err)
		}
		if n <= 0 {
			return
		}
		length := n
		sended := 0
		for {
			n, _ := dst.Write(data[sended:length])
			if err != nil {
				log.Println(err)
			}
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
	err = ConnectEx(remote, data[:], sa)
	return remote, err
}

func ConnectEx(fd handle, p []byte, to syscall.Sockaddr) error {
	err := syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_FASTOPEN, 1)
	if err != nil {
		log.Println(err)
		return err
	}
	bindsa := &syscall.SockaddrInet4{Addr: [4]byte{0, 0, 0, 0}, Port: 0}
	syscall.Bind(fd, bindsa)
	var bytesSent uint32
	var overlapped syscall.Overlapped = syscall.Overlapped{0, 0, 0, 0, 0}
	var data syscall.WSABuf
	data.Len = uint32(len(p))
	data.Buf = (*byte)(unsafe.Pointer(&p))

	err = syscall.ConnectEx(fd, to,
		(*byte)(unsafe.Pointer(&p)), uint32(len(p)),
		&bytesSent, &overlapped)
	if err != nil {
		if err == syscall.ERROR_IO_PENDING {
			_, err := syscall.WaitForSingleObject(fd, 2000)
			if err != nil {
				log.Println(err)
			}
		} else {
			log.Println(err)
			return err
		}
	}
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_UPDATE_CONNECT_CONTEXT, 0)
	if err != nil {
		log.Println(err)
		return err
	}
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
	if err != nil {
		log.Println(err)
		return err
	}

	if bytesSent < uint32(len(p)) {
		err = syscall.WSASend(fd, &data, 1, &bytesSent, 0, &overlapped, nil)
		if err != nil {
			log.Println(err)
			return err
		}
	}

	return err
}

func Connect(fd handle, to syscall.Sockaddr) error {
	err := syscall.Connect(fd, to)
	if err != nil {
		return err
	}
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
	return err
}

func SetTCPMaxSeg(fd handle, mss int) error {
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_MAXSEG, mss)
}

func SetTCPKeepAlive(fd handle, keep bool) error {
	if keep {
		err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)
		return err
	} else {
		return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 0)
	}
}

func GetOriginalDST(conn *net.TCPConn) (*net.TCPAddr, error) {
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
	return Proxy(client, address)
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

func TTLProxyHost(serverAddrList []net.TCPAddr, option string, client net.Conn, host string, port int, mss int) {
	//TODO
}

func TTLSProxyHost(serverAddrList []net.TCPAddr, option string, client net.Conn, host string, port int, mss int) {
	//TODO
}
