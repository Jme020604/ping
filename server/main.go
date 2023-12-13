package main

import (
	"chat/server/messageHandeler"
	"fmt"
	"net"
	"sync"
)

var wg sync.WaitGroup

func server(ip net.IP) {
	fmt.Println("starting server for listening")
	adress := fmt.Sprint(ip, ":8080")
	listener, err := net.Listen("tcp", adress)
	if err != nil {
		fmt.Println("Error starting server:", err)
		return
	}
	defer listener.Close()

	fmt.Println("Server is running on ", adress)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		} else {
			fmt.Println("connected to:", conn.RemoteAddr())
		}

		wg.Add(1)
		go messageHandeler.HandleConnection(conn, &wg)
	}

}

func checkIp() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		fmt.Println(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

func main() {
	ip := checkIp()
	server(ip)

	wg.Wait()
}
