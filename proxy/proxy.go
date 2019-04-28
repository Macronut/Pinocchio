// +build !windows

package proxy

import (
	"crypto/cipher"
	"encoding/binary"
	"math/rand"
	"net"
	"strings"
	"syscall"
	"time"
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
	"CRYPTO",
	"CRYPTO_TFO",
	"CRYPTO_SNI",
	"CRYPTO_SNITFO",
	"KCP",
	"KCPMUX",
}

const BUFFER_SIZE int = 65536
const SOL_TCP = syscall.SOL_TCP

var LogEnable = false

type handle = int

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
	for {
		n, _ := syscall.Read(src, data)
		if n <= 0 {
			syscall.Close(src)
			dst.Close()
			return
		}
		length := n
		sended := 0
		for {
			n, _ := dst.Write(data[sended:length])
			if n <= 0 {
				syscall.Close(src)
				dst.Close()
				return
			}
			sended += n
			if sended == length {
				break
			}
		}
	}
}

func ForwardFromSocketSpeed(src int, dst net.Conn, speed int) {
	data := make([]byte, BUFFER_SIZE)
	defer syscall.Close(src)
	defer dst.Close()
	flow := 0
	startTime := time.Now()
	for {
		n, _ := syscall.Read(src, data)
		if n <= 0 {
			return
		}
		flow += n
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
		t := time.Since(startTime)
		t = time.Duration(flow)*time.Second/time.Duration(speed) - t
		if t > 0 {
			time.Sleep(t)
		}
	}
}

func CipherForward(server handle, client net.Conn, stream cipher.Stream) {
	data := make([]byte, BUFFER_SIZE)
	defer syscall.Close(server)
	for {
		n, _ := syscall.Read(server, data)
		if n <= 0 {
			return
		}
		//syscall.SetsockoptInt(server, SOL_TCP, syscall.TCP_QUICKACK, 1)

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

var BindAddrMap4 map[string][4]byte = make(map[string][4]byte)
var BindAddrMap6 map[string][16]byte = make(map[string][16]byte)

func BindInterface(fd handle, iface string) (syscall.Sockaddr, error) {
	if len(iface) == 0 {
		return nil, nil
	}

	addr, ok := BindAddrMap4[iface]
	if ok {
		bindsa := new(syscall.SockaddrInet4)
		bindsa.Addr = addr
		bindsa.Port = 0
		err := syscall.Bind(fd, bindsa)
		if err == nil {
			return bindsa, nil
		}
	}

	inf, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	addrs, _ := inf.Addrs()
	for _, addr := range addrs {
		bindaddr, ok := addr.(*net.IPNet)
		if ok {
			if bindaddr.IP.To4() != nil {
				var addr [4]byte
				copy(addr[:4], bindaddr.IP[12:])
				bindsa := new(syscall.SockaddrInet4)
				bindsa.Addr = addr
				bindsa.Port = 0
				err = syscall.Bind(fd, bindsa)
				if err != nil {
					return nil, err
				}
				BindAddrMap4[iface] = addr
				return bindsa, nil
			}
		}
	}
	return nil, nil
}

func BindInterface6(fd handle, iface string) (syscall.Sockaddr, error) {
	if len(iface) == 0 {
		return nil, nil
	}

	addr, ok := BindAddrMap6[iface]
	if ok {
		bindsa := new(syscall.SockaddrInet6)
		bindsa.Addr = addr
		bindsa.Port = 0
		err := syscall.Bind(fd, bindsa)
		if err == nil {
			return bindsa, nil
		}
	}

	inf, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	addrs, _ := inf.Addrs()
	for _, addr := range addrs {
		bindaddr, ok := addr.(*net.IPNet)
		if ok {
			if bindaddr.IP.To4() == nil {
				var addr [16]byte
				copy(addr[:16], bindaddr.IP)
				bindsa := new(syscall.SockaddrInet6)
				bindsa.Addr = addr
				bindsa.Port = 0
				err = syscall.Bind(fd, bindsa)
				if err != nil {
					return nil, err
				}
				BindAddrMap6[iface] = addr
				return bindsa, nil
			}
		}
	}
	return nil, nil
}

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

		if TCPAddr.IP.Equal(LocalTCPAddr.IP) {
			return nil, nil
		}

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
