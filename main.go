package main

import (
	"fmt"
	"net"
	"strings"
)

func main() {
	fmt.Println("Listerning on port 53")
	ln, err := net.Listen("tcp4", ":53")
	if err != nil {
		fmt.Println("Error: ", err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error: ", err)
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	buffer := make([]byte, 1024)
	var stringBuilder strings.Builder
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Println("Error: ", err)
	}
	stringBuilder.Write(buffer[:n])

	for n > 0 {
		n, err = conn.Read(buffer)
		if err != nil {
			fmt.Println("Error: ", err)
			break
		}
		stringBuilder.Write(buffer[:n])
	}

	fmt.Println()
	fmt.Println(stringBuilder.String())
	conn.Close()
}
