package proxy

import (
	"encoding/binary"
	"log"
	"math/rand"
	"net"
)

func GetRealHost(client net.Conn) (string, int) {
	var b [1024]byte
	n, err := client.Read(b[:])
	if err != nil {
		log.Println(err)
		return "", 0
	}
	if b[0] == 0x05 {
		client.Write([]byte{0x05, 0x00})
		n, err = client.Read(b[:])
		if err != nil {
			return "", 0
		}
		var host string
		switch b[3] {
		case 0x01:
			host = net.IPv4(b[4], b[5], b[6], b[7]).String()
		case 0x03:
			host = string(b[5 : n-2])
		case 0x04:
			host = net.IP{b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19]}.String()
		}
		port := int(b[n-2])<<8 | int(b[n-1])
		client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

		return host, port
	}
	return "", 0
}

func SocksProxyAddr(serverAddrList []net.TCPAddr, client net.Conn, address *net.TCPAddr) {
	addr, err := net.ResolveTCPAddr("tcp", ":0")
	serverAddr := serverAddrList[rand.Intn(len(serverAddrList))]
	server, err := net.DialTCP("tcp", addr, &serverAddr)
	if err != nil {
		log.Println(err)
		return
	}
	defer server.Close()

	err = server.SetKeepAlive(true)
	if err != nil {
		log.Println(err)
		return
	}

	var b [1024]byte
	_, err = server.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		log.Println(err)
		return
	}
	_, err = server.Read(b[:])
	if err != nil {
		log.Println(err)
		return
	}
	if b[0] == 0x05 {
		headLen := 4
		IP := []byte(address.IP)
		if len(IP) == 4 {
			copy(b[:], []byte{0x05, 0x01, 0x00, 0x01})
			copy(b[4:], IP)
			headLen += 4
		} else {
			copy(b[:], []byte{0x05, 0x01, 0x00, 0x04})
			copy(b[4:], IP)
			headLen += 16
		}
		binary.BigEndian.PutUint16(b[headLen:], uint16(address.Port))
		headLen += 2
		_, err = server.Write(b[:headLen])
		if err != nil {
			log.Println(err)
			return
		}
		n, err := server.Read(b[:])
		if err != nil {
			log.Println(err)
			return
		}
		if n < 2 {
			return
		}
		if b[0] != 0x05 {
			return
		}
	}

	go Forward(server, client)
	Forward(client, server)
}

func SocksProxyHost(serverAddrList []net.TCPAddr, client net.Conn, host string, port int) {
	addr, err := net.ResolveTCPAddr("tcp", ":0")
	serverAddr := serverAddrList[rand.Intn(len(serverAddrList))]
	server, err := net.DialTCP("tcp", addr, &serverAddr)
	if err != nil {
		log.Println(err)
		return
	}
	defer server.Close()

	err = server.SetKeepAlive(true)
	if err != nil {
		log.Println(err)
		return
	}

	var b [1024]byte
	_, err = server.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		log.Println(err)
		return
	}
	_, err = server.Read(b[:])
	if err != nil {
		log.Println(err)
		return
	}
	if b[0] == 0x05 {
		copy(b[:], []byte{0x05, 0x01, 0x00, 0x03})
		bHost := []byte(host)
		hostLen := len(bHost)
		b[4] = byte(hostLen)
		copy(b[5:], bHost)
		binary.BigEndian.PutUint16(b[5+hostLen:], uint16(port))
		_, err = server.Write(b[:7+hostLen])
		if err != nil {
			log.Println(err)
			return
		}
		n, err := server.Read(b[:])
		if err != nil {
			log.Println(err)
			return
		}
		if n < 2 {
			return
		}
		if b[0] == 0x00 {
			return
		}
	}

	go Forward(server, client)
	Forward(client, server)
}
