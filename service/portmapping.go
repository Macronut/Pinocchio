package service

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"../proxy"
)

var UDPLock sync.RWMutex
var UDPMap map[string]net.Conn

func UDPMapping(ProxyAddress net.UDPAddr, Host string) error {
	client, err := net.ListenUDP("udp", &ProxyAddress)
	if err != nil {
		log.Println(err)
		return err
	}
	defer client.Close()

	if LogEnable {
		fmt.Println("UDPMapping:", Host, ProxyAddress.String())
	}

	UDPMap = make(map[string]net.Conn)
	data := make([]byte, 1500)

	for {
		n, clientAddr, err := client.ReadFromUDP(data)
		if err != nil {
			log.Println(err)
			return err
		}

		UDPLock.Lock()
		udpConn, ok := UDPMap[clientAddr.String()]
		UDPLock.Unlock()

		if ok {
			udpConn.Write(data[:n])
		} else {
			if len(Host) > 0 {
				if LogEnable {
					fmt.Println("[UDP]", clientAddr.String(), Host)
				}
				udpConn, err = net.Dial("udp", Host)
				if err != nil {
					log.Println(err)
					continue
				}

				UDPMap[clientAddr.String()] = udpConn
				_, err = udpConn.Write(data[:n])
				if err != nil {
					log.Println(err)
					continue
				}

				go func(clientAddr net.UDPAddr) {
					data := make([]byte, 1500)
					udpConn.SetReadDeadline(time.Now().Add(time.Minute * 2))
					for {
						n, err := udpConn.Read(data)
						if err != nil {
							QUICLock.Lock()
							delete(QUICMap, clientAddr.String())
							QUICLock.Unlock()
							udpConn.Close()
							return
						}
						udpConn.SetReadDeadline(time.Now().Add(time.Minute * 2))
						client.WriteToUDP(data[:n], &clientAddr)
					}
				}(*clientAddr)
			}
		}
	}
}

func UDPMapping2(ProxyAddress net.UDPAddr, Host string) error {
	client, err := net.ListenUDP("udp", &ProxyAddress)
	if err != nil {
		log.Println(err)
		return err
	}
	defer client.Close()

	if LogEnable {
		fmt.Println("UDPMapping:", Host, ProxyAddress.String())
	}

	UDPMap = make(map[string]net.Conn)
	data := make([]byte, 1500)

	udpConn, err := net.Dial("udp", Host)

	for {
		n, clientAddr, err := client.ReadFromUDP(data)
		if err != nil {
			log.Println(err)
			return err
		}

		udpConn.Write(data[:n])

		go func() {
			data := make([]byte, 1500)
			for {
				n, err := udpConn.Read(data)
				if err != nil {
					log.Println(err)
					udpConn.Close()
					return
				}
				client.WriteToUDP(data[:n], clientAddr)
			}
		}()
	}
}

func TCPMapping(ProxyAddress net.TCPAddr, Host string) error {
	l, err := net.ListenTCP("tcp", &ProxyAddress)
	if err != nil {
		log.Println(err)
		return err
	}
	defer l.Close()

	if LogEnable {
		fmt.Println("TCPMapping:", Host, ProxyAddress.String())
	}

	for {
		client, err := l.AcceptTCP()
		if err != nil {
			log.Println(err)
			return err
		}

		if len(ProxyClients) > 0 {
			RemoteAddr := client.RemoteAddr()
			RemoteTCPAddr, _ := net.ResolveTCPAddr(RemoteAddr.Network(), RemoteAddr.String())
			strIP := RemoteTCPAddr.IP.String()
			_, ok := ProxyClients[strIP]
			if !ok {
				if LogEnable {
					fmt.Println(strIP, "Forbidden")
				}
				client.Close()
				continue
			}
		}

		if LogEnable {
			fmt.Println("[TCP]", client.RemoteAddr().String(), Host)
		}

		go proxy.Proxy(client, Host)
	}
	return nil
}

func TFOMapping(ProxyAddress net.TCPAddr, Host string) error {
	l, err := net.ListenTCP("tcp", &ProxyAddress)
	if err != nil {
		log.Println(err)
		return err
	}
	defer l.Close()

	if LogEnable {
		fmt.Println("TFOMapping:", Host, ProxyAddress.String())
	}

	for {
		client, err := l.AcceptTCP()
		if err != nil {
			log.Println(err)
			return err
		}

		if len(ProxyClients) > 0 {
			RemoteAddr := client.RemoteAddr()
			RemoteTCPAddr, _ := net.ResolveTCPAddr(RemoteAddr.Network(), RemoteAddr.String())
			strIP := RemoteTCPAddr.IP.String()
			_, ok := ProxyClients[strIP]
			if !ok {
				if LogEnable {
					fmt.Println(strIP, "Forbidden")
				}
				client.Close()
				continue
			}
		}

		if LogEnable {
			fmt.Println("[TCP]", client.RemoteAddr().String(), Host)
		}

		go proxy.ProxyTFO(client, Host, nil)
	}
	return nil
}
