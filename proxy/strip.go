package proxy

import (
	"crypto/tls"
	"log"
	"math/rand"
	"net"
	//"strings"
)

func StripHost(serverAddrList []AddrInfo, fronting string, client net.Conn, host string, port int, headdata []byte) {
	defer client.Close()

	serverAddr := serverAddrList[rand.Intn(len(serverAddrList))].Address
	IP := serverAddr.IP

	if port == 443 {
		err := Proxy(client, net.JoinHostPort(IP.String(), "443"))
		if err != nil {
			log.Println(err)
			return
		}
		return
	}

	var conf *tls.Config
	if len(fronting) == 0 {
		conf = &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		}
	} else if fronting == "NOSNI" {
		conf = &tls.Config{
			InsecureSkipVerify: true,
		}
	} else {
		conf = &tls.Config{
			ServerName:         fronting,
			InsecureSkipVerify: true,
		}
	}

	server, err := tls.Dial("tcp", net.JoinHostPort(IP.String(), "443"), conf)
	if err != nil {
		log.Println(err)
		return
	}

	defer server.Close()
	data := make([]byte, BUFFER_SIZE)
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

	n, err = server.Write(data[:n])
	if err != nil {
		log.Println(err)
		return
	}

	go func() {
		for {
			n, err := client.Read(data)
			if n <= 0 {
				return
			}
			n, err = server.Write(data[:n])
			if err != nil {
				log.Println(err)
				return
			}
		}
	}()

	for {
		n, err := server.Read(data)
		if n <= 0 {
			return
		}
		n, err = client.Write(data[:n])
		if err != nil {
			log.Println(err)
			return
		}
	}
}
