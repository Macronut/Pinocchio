package proxy

import (
	"log"
	"time"

	//"math/rand"
	"net"
	//"syscall"
)

func ForwardProxyHost(serverAddr *net.TCPAddr, client net.Conn, host string, port int) {
	addr, err := net.ResolveTCPAddr("tdp", ":0")
	server, err := net.DialTCP("tcp", addr, serverAddr)
	if err != nil {
		log.Println(err)
		return
	}
	defer server.Close()

	data := make([]byte, 2048)

	go Forward(server, client)

	for {
		n, err := client.Read(data)
		if LogEnable && err != nil {
			log.Println(n, err)
		}
		if n <= 0 {
			return
		}

		client.SetReadDeadline(time.Now().Add(CONN_TTL))

		if n == 0 {
			return
		}
		n, err = server.Write(data[:n])
		if err != nil {
			log.Println(err)
			return
		}
	}
}
