package proxy

import (
	"bytes"
	"encoding/binary"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/williamfhe/godivert"
)

func htons(h uint16) uint16 {
	return ((h >> 8) & 0xFF) | ((h & 0xFF) << 8)
}

var MystifyMSSMutex sync.Mutex
var MSSDaemonEnable = false
var MystifyMSSMap map[string]uint16

func MystifyMSSDaemon() {
	filter := "tcp.Syn and tcp.DstPort == 443"
	winDivert, err := godivert.NewWinDivertHandle(filter)
	if err != nil {
		log.Println(err, filter)
		return
	}
	defer winDivert.Close()

	for {
		packet, err := winDivert.Recv()
		if err != nil {
			log.Println(err)
			return
		}

		ipheadlen := int(packet.Raw[0]&0xF) * 4
		if len(packet.Raw) >= ipheadlen+24 {
			MystifyMSSMutex.Lock()
			mss, ok := MystifyMSSMap[packet.DstIP().String()]
			MystifyMSSMutex.Unlock()
			if ok {
				option := packet.Raw[ipheadlen+20]
				if option == 2 {
					binary.BigEndian.PutUint16(packet.Raw[ipheadlen+22:], uint16(mss))
					packet.CalcNewChecksum(winDivert)
				}
			}
		}

		_, err = winDivert.Send(packet)
		if err != nil {
			log.Println(err)
			continue
		}
	}
}

func MystifyConnect(laddr, raddr *net.TCPAddr, mss uint16) (*net.TCPConn, error) {
	host := raddr.IP.String()
	filter := "ip.DstAddr == " + host + " and tcp.Syn and tcp.DstPort == " + strconv.Itoa(raddr.Port)
	winDivert, err := godivert.NewWinDivertHandle(filter)
	if err != nil {
		log.Println(err, filter)
		return nil, err
	}

	go func() {
		defer winDivert.Close()

		packet, err := winDivert.Recv()
		if err != nil {
			log.Println(err)
			return
		}

		ipheadlen := int(packet.Raw[0]&0xF) * 4
		if len(packet.Raw) < ipheadlen+24 {
			log.Println(packet)
			return
		}
		//offset := packet.Raw[ipheadlen+12] >> 4
		option := packet.Raw[ipheadlen+20]
		if option == 2 {
			binary.BigEndian.PutUint16(packet.Raw[ipheadlen+22:], mss)
			packet.CalcNewChecksum(winDivert)

			_, err = winDivert.Send(packet)
			_, err = winDivert.Send(packet)
			if err != nil {
				log.Println(err)
				return
			}
		}
	}()

	conn, err := net.DialTCP("tcp4", laddr, raddr)
	return conn, err
}

const letterBytes = "0123456789abcdefghijklmnopqrstuvwxyz"

func RandStringBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return b
}

func MystifySend(conn *net.TCPConn, data []byte, addr *net.TCPAddr, ttl int, host string) error {
	localAddr := conn.LocalAddr()
	laddr, err := net.ResolveTCPAddr(localAddr.Network(), localAddr.String())

	filter := "tcp.Psh and tcp.SrcPort == " + strconv.Itoa(laddr.Port)
	winDivert, err := godivert.NewWinDivertHandle(filter)

	if err != nil {
		log.Println(err, filter)
		return err
	}
	defer winDivert.Close()

	rawbuf := make([]byte, 1500)
	fakedata := make([]byte, len(data))

	hostbyte := []byte(host)
	if len(host) > 0 {
		copy(fakedata[:], data)
		fakedata = bytes.Replace(fakedata, hostbyte, RandStringBytes(len(hostbyte)), 1)
	}

	hostOffset := 0
	if host != "" {
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
			_, err = conn.Write(data[:hostOffset])
			if err != nil {
				return err
			}

			packet, err := winDivert.Recv()
			if err != nil {
				return err
			}

			fake_packet := *packet
			copy(rawbuf[:], packet.Raw[:len(packet.Raw)-hostOffset])
			rawbuf[8] = byte(ttl)
			fake_packet.Raw = rawbuf[:len(packet.Raw)]
			fake_packet.CalcNewChecksum(winDivert)

			_, err = winDivert.Send(&fake_packet)
			if err != nil {
				log.Println(host, err)
				return err
			}

			_, err = winDivert.Send(packet)
			if err != nil {
				log.Println(host, err)
				return err
			}
		}
	}

	_, err = conn.Write(data[hostOffset:])
	if err != nil {
		log.Println(host, err)
		return err
	}

	packet, err := winDivert.Recv()
	if err != nil {
		return err
	}

	fake_packet := *packet
	copy(rawbuf[:], packet.Raw[:len(packet.Raw)-len(data)+hostOffset])
	rawbuf[8] = byte(ttl)
	fake_packet.Raw = rawbuf[:len(packet.Raw)]
	fake_packet.CalcNewChecksum(winDivert)

	_, err = winDivert.Send(&fake_packet)
	if err != nil {
		log.Println(host, err)
		return err
	}

	_, err = winDivert.Send(packet)
	if err != nil {
		log.Println(host, err)
		return err
	}

	return nil
}

func MystifyProxy(serverAddrList []AddrInfo, option string, client net.Conn, host string, port int, ttl int, mss int, headdata []byte) {
	defer client.Close()

	serverAddrCount := len(serverAddrList)
	if serverAddrCount == 0 {
		return
	}

	var err error
	addressInfo := serverAddrList[rand.Intn(serverAddrCount)]
	serverAddr := addressInfo.Address
	serverAddr.Port = port

	/*
		var iface string
		if len(addressInfo.Interface) == 0 {
			ifaces := strings.Split(option, "|")
			iface = ifaces[rand.Intn(len(ifaces))]
		} else {
			iface = addressInfo.Interface
		}

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
	*/

	var server *net.TCPConn
	if mss > 0 {
		MystifyMSSMutex.Lock()
		if MSSDaemonEnable == false {
			MSSDaemonEnable = true
			MystifyMSSMap = make(map[string]uint16)
			go MystifyMSSDaemon()
		}
		MystifyMSSMap[serverAddr.IP.String()] = uint16(mss)
		MystifyMSSMutex.Unlock()
	}

	server, err = net.DialTCP("tcp4", nil, &serverAddr)
	if err != nil {
		log.Println(host, err)
		return
	}
	defer server.Close()

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

	err = MystifySend(server, data[:n], &serverAddr, ttl, host)
	if err != nil {
		log.Println(host, serverAddr, err)
		return
	}

	go Forward(server, client)

	if mss > 0 {
		//Restore MSS
		n, err = client.Read(data)
		if n <= 0 {
			return
		}
		/*
			if mss > 0 {
				err = SetTCPMaxSeg(server, 1452)
				if err != nil {
					log.Println(err)
					return
				}
			}
		*/
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

	var err error

	addressInfo := serverAddrList[rand.Intn(serverAddrCount)]
	serverAddr := addressInfo.Address

	server, err := net.DialTCP("tcp4", nil, &serverAddr)
	if err != nil {
		log.Println(host, err)
		return
	}
	defer server.Close()

	go Forward(server, client)

	data := make([]byte, 1460)
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

		err = MystifySend(server, []byte(request), &serverAddr, ttl, host)
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

	server, err := net.DialTCP("tcp", nil, serverAddr)
	defer server.Close()

	data := make([]byte, 4096)
	binary.BigEndian.PutUint16(data[:2], uint16(len(request)))
	copy(data[2:], request)

	err = MystifySend(server, data[:len(request)+2], serverAddr, ttl, "")
	if err != nil {
		return nil, err
	}

	length := 0
	recvlen := 0
	for {
		n, err := server.Read(data[length:])
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
