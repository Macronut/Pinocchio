package proxy

import (
	"log"
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
		if err != nil {
			log.Println(err)
			return
		}
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
