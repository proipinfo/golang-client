package main

import (
	"fmt"
	"net"

	proip "github.com/proipinfo/golang-client"
)

func main() {
	ipv4 := net.ParseIP("8.8.8.8")
	ipv6 := net.ParseIP("dead::beaf")
	path := "path/to/db"
	db, err := proip.NewGDBCClient(path)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	// ip v4
	recV4, err := db.GetRecord(ipv4)
	if err != nil {
		panic(err)
	}
	fmt.Println(recV4.City)

	// ip v6
	recV6, err := db.GetRecord(ipv6)
	if err != nil {
		panic(err)
	}
	fmt.Println(recV6.City)
}
