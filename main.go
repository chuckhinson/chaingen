package main

import (
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"strings"

	"github.com/chuckhinson/chaingen/internal/cert"
)

func main() {

	var serverName string
	flag.StringVar(&serverName, "host", "test.example.com", "hostname for certificate")
	flag.Parse()

	if !cert.IsValidDomain(serverName) {
		panic("host name is not a valid name")
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	chain, err := cert.MakeCertChain(serverName, serverKey.PublicKey)
	if err != nil {
		panic(err)
	}

	prefix := strings.ToLower(serverName)
	prefix = strings.Replace(serverName, "*", "STAR", 1)
	prefix = strings.ReplaceAll(prefix, ".", "_")
	err = cert.WritePEMFiles(chain, serverKey, prefix)
	if err != nil {
		panic(err)
	}

}
