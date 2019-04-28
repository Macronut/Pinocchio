package proxy

import (
	"bytes"
	"strconv"

	//"encoding/binary"
	"log"
	"math/rand"
	"net"

	//"strings"
	//"syscall"
	//"time"

	//"../net/ipv4"
	//"../net/tcp"
	"github.com/williamfhe/godivert"
)

func htons(h uint16) uint16 {
	return ((h >> 8) & 0xFF) | ((h & 0xFF) << 8)
}

/*
func MystifyConnect(raddr, laddr *net.TCPAddr, timeout int) (*net.TCPConn, TCPInfo, error) {
	var connInfo = TCPInfo{0, 0, 0, 0, 0}

	winDivert, err := godivert.NewWinDivertHandle("tcp.Syn and tcp.SrcPort == 443")
	if err != nil {
		log.Println(err)
		return nil, connInfo, err
	}
	defer winDivert.Close()

	conn, err := net.DialTCP("tcp4", laddr, raddr)
	if err != nil {
		log.Println(err)
		return nil, connInfo, err
	}

	ch := make(chan TCPInfo)
	LocalAddr := conn.LocalAddr()
	LocalTCPAddr, err := net.ResolveTCPAddr(LocalAddr.Network(), LocalAddr.String())
	iSockIP := binary.BigEndian.Uint32(LocalTCPAddr.IP[:4])
	sockPort := uint16(LocalTCPAddr.Port)
	PortChan[sockPort] = ch
	defer func() {
		PortChan[sockPort] = nil
	}()

	go func() {
		for {
			var ipheader ipv4.Header
			var tcpheader tcp.Header

			packet, err := winDivert.Recv()
			if err != nil {
				return
			}
			if packet.PacketLen < 40 {
				continue
			}

			log.Println(packet)

			err = ipheader.Parse(packet.Raw)
			if err != nil {
				log.Println(err)
				continue
			}

			iDstIP := binary.BigEndian.Uint32(ipheader.Dst.To4())
			if iDstIP != iSockIP {
				continue
			}

			err = tcpheader.Parse(packet.Raw[ipheader.Len:])
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
		return nil, connInfo, syscall.ETIMEDOUT
	}

	return conn, connInfo, nil
}
*/
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

	_, err = conn.Write(data[hostOffset:])
	if err != nil {
		log.Println(host, err)
		return err
	}

	packet, err = winDivert.Recv()
	if err != nil {
		return err
	}
	fake_packet = *packet
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

	//server, connInfo, err := MystifyConnect(&serverAddr, nil, 6)
	server, err := net.DialTCP("tcp4", nil, &serverAddr)
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
