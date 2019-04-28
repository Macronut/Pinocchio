package proxy

import (
	"crypto/cipher"
	"encoding/binary"
	"log"
	"math/rand"
	"net"
	"strings"
	"syscall"
	"unsafe"
)

const (
	NULL = iota
	HTTP
	HTTPS
	IPv6to4
	SOCKS
	IPv4to6

	MOVE
	BIND
	MYSTIFY
	MYSTIFY6
	MYTCPMD5
	MYHTTP
	MYHTTP6
	TFO
	STRIP

	TYPE_COUNT
)

var TypeList [TYPE_COUNT]string = [TYPE_COUNT]string{
	"NULL",
	"HTTP",
	"HTTPS",
	"IPv6to4",
	"SOCKS",
	"IPv4to6",
	"MOVE",
	"BIND",
	"MYSTIFY",
	"MYSTIFY6",
	"MYTCPMD5",
	"MYHTTP",
	"MYHTTP6",
	"TFO",
	"STRIP",
}

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

var LogEnable = false

type handle = syscall.Handle

type AddrInfo struct {
	Address   net.TCPAddr
	Interface string
}

type ProxyInfo struct {
	Type     uint8
	TTL      uint8
	MSS      uint16
	AddrList []AddrInfo
	Option   string
}

func SendAll(sock net.Conn, data []byte) (int, error) {
	length := len(data)
	sended := 0
	for {
		n, err := sock.Write(data[sended:])
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

func CipherForward(server net.Conn, client net.Conn, stream cipher.Stream) {
	data := make([]byte, BUFFER_SIZE)
	defer server.Close()
	for {
		n, _ := server.Read(data)
		if n <= 0 {
			return
		}

		stream.XORKeyStream(data, data[:n])
		length := n
		sended := 0
		for {
			n, _ = client.Write(data[sended:length])
			sended += n

			if n <= 0 {
				return
			}
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
	go Forward(server, client)
	Forward(client, server)

	return nil
}

func ProxyTFO(client net.Conn, address string, headData []byte) error {
	var data [2048]byte
	var n int
	var err error

	if len(headData) > 0 {
		n = len(headData)
		copy(data[:], headData)
	} else {
		n, err = client.Read(data[:])
		if n <= 0 {
			return err
		}
	}

	server, err := net.Dial("tcp", address)
	if err != nil {
		return err
	}

	server.Write(data[:n])

	go Forward(server, client)
	Forward(client, server)

	return nil
}

func ProxyAddress(client net.Conn, serverAddrList []AddrInfo, port int) error {
	serverAddrCount := len(serverAddrList)
	if serverAddrCount == 0 {
		return nil
	}
	serverAddr := serverAddrList[rand.Intn(serverAddrCount)].Address
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

func ProxyAddressBind(client net.Conn, serverAddrList []AddrInfo, port int, iface string) error {
	serverAddrCount := len(serverAddrList)
	if serverAddrCount == 0 {
		return nil
	}
	serverAddr := serverAddrList[rand.Intn(serverAddrCount)].Address
	serverAddr.Port = port

	ief, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	addrs, err := ief.Addrs()
	if err != nil {
		return err
	}

	tcpAddr := &net.TCPAddr{
		IP: addrs[0].(*net.IPNet).IP,
	}

	server, err := net.DialTCP("tcp", tcpAddr, &serverAddr)
	if err != nil {
		return err
	}
	defer server.Close()

	go Forward(server, client)
	Forward(client, server)

	return nil
}

func MoveHttps(data []byte, client net.Conn) bool {
	if data[0] == 0x16 {
		return false
	}
	header := string(data)
	if header[:4] != "GET " {
		return false
	}
	d := make([]byte, 1024)
	start := strings.Index(header, "Host: ") + 6
	end := strings.Index(header[start:], "\r\n") + start
	n := 0
	copy(d[:], []byte("HTTP/1.1 301 TLS Redirect\r\nLocation: https://"))
	n += 45
	copy(d[n:], []byte(header[start:end]))
	n += end - start
	start = strings.Index(header, " /") + 1
	end = strings.Index(header[start:], " ") + start
	copy(d[n:], []byte(header[start:end]))
	n += end - start
	copy(d[n:], []byte("\r\nContent-Length: 0\r\n\r\n"))
	n += 23
	client.Write(d[:n])
	return true
}

func MoveHttp(header string, host string, client net.Conn) bool {
	data := make([]byte, BUFFER_SIZE)
	n := 0
	if host == "" {
		if header[:4] != "GET " {
			return true
		}
		copy(data[:], []byte("HTTP/1.1 200 OK"))
		n += 15
	} else if host == "https" {
		if header[:4] != "GET " {
			return false
		}
		copy(data[:], []byte("HTTP/1.1 302 Found\r\nLocation: https://"))
		n += 38

		start := strings.Index(header, "Host: ") + 6
		end := strings.Index(header[start:], "\r\n") + start
		copy(data[n:], []byte(header[start:end]))
		n += end - start

		start = 4
		end = strings.Index(header[start:], " ") + start
		copy(data[n:], []byte(header[start:end]))
		n += end - start
	} else {
		if header[:4] != "GET " {
			return false
		}
		copy(data[:], []byte("HTTP/1.1 302 Found\r\nLocation: "))
		n += 30
		copy(data[n:], []byte(host))
		n += len(host)

		start := 4
		end := strings.Index(header[start:], " ") + start
		copy(data[n:], []byte(header[start:end]))
		n += end - start
	}

	copy(data[n:], []byte("\r\nCache-Control: private\r\nServer: pinocchio\r\nContent-Length: 0\r\n\r\n"))
	n += 66
	client.Write(data[:n])
	return true
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
			return string(b[offset : offset+int(ServerNameLength)])
		} else {
			offset += int(ExtensionLength)
		}
	}
	return ""
}

func GetQUICSNI(b []byte) string {
	if len(b) < 54 {
		return ""
	}
	//CID := string(b[1:9])
	//Version := string(b[9:13])
	//PacketNumber := b[13]
	//AuthHash := b[14:26]
	FramType := b[26]
	if FramType == 0xA0 {
		//StreamID := b[27]
		//DataLen := binary.LittleEndian.Uint16(b[28:30])
		Tag := string(b[30:34])
		if Tag == "CHLO" {
			TagNumber := binary.LittleEndian.Uint16(b[34:36])
			//Padding := binary.LittleEndian.Uint16(b[36:38])
			offset := 38 + TagNumber*8
			start := offset
			for i := 0; i < int(TagNumber); i++ {
				tagStart := 38 + i*8
				TagName := string(b[tagStart : tagStart+4])
				end := binary.LittleEndian.Uint16(b[tagStart+4 : tagStart+8])
				end += offset
				//fmt.Println("[QUIC]", TagName, end)
				if TagName == "SNI\x00" {
					return string(b[start:end])
				}
				start = end
			}
		}
	}
	return ""
}

func GetHost(b []byte) string {
	header := string(b)
	start := strings.Index(header, "Host: ") + 6
	if start == -1 {
		return ""
	}
	end := strings.Index(header[start:], "\r\n")
	if end == -1 {
		return ""
	}
	end += start
	return header[start:end]
}

func MystifyProxyHTTP(serverAddrList []AddrInfo, option string, client net.Conn, host string, port int, ttl int, mss int) {
}
func MystifyProxy6(serverAddrList []AddrInfo, option string, client net.Conn, host string, port int, ttl int, mss int, md5 bool, headdata []byte) {
}
func MystifyProxyHTTP6(serverAddrList []AddrInfo, option string, client net.Conn, host string, port int, ttl int, mss int, md5 bool) {
}
func ForceTFOProxyHost(serverAddrList []AddrInfo, option string, client net.Conn, host string, port int, mss int, headdata []byte) {
}
func MoveProxyHost(serverAddrList []AddrInfo, client net.Conn, host string, port int, mss int, headdata []byte) {
}
func BindProxyAddr(serverAddrList []AddrInfo, option string, client net.Conn, address *net.TCPAddr, mss int, tfo bool) {
}
func BindProxyHost(serverAddrList []AddrInfo, option string, client net.Conn, host string, port int, mss int, headdata []byte) {
}
func TFOProxyHost(serverAddrList []AddrInfo, option string, client net.Conn, host string, port int, mss int, headdata []byte) {
}
func MystifyTCPLookup(request []byte, address string, ttl int) ([]byte, error) {
	return nil, nil
}
