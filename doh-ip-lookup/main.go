/*
   DNS-over-HTTPS
   Copyright (C) 2017-2018 Star Brilliant <m13253@hotmail.com>
*/

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/m13253/dns-over-https/v2/doh-client/shmmap"
)

const version = "2.3.10"

func main() {
	shmName := flag.String("shm-name", "/doh-client-dns-map", "POSIX shared memory name used by doh-client")
	showVersion := flag.Bool("version", false, "Show software version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("doh-ip-lookup %s\nHomepage: https://github.com/m13253/dns-over-https\n", version)
		return
	}

	args := flag.Args()
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "Usage: doh-ip-lookup [-shm-name NAME] IP\n")
		os.Exit(1)
	}

	ip := net.ParseIP(args[0])
	if ip == nil {
		log.Fatalf("invalid IP address: %s", args[0])
	}

	store, err := shmmap.OpenReadOnly(*shmName)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	domain, ok := store.Lookup(ip)
	if !ok {
		log.Fatalf("no domain found for IP %s", ip)
	}

	fmt.Println(domain)
}
