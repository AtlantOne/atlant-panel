// Generates ephemeral certificates for the Python control-service TLS tests.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"time"
)

type pair struct {
	Certificate string `json:"certificate"`
	Key         string `json:"key"`
}

func certificate(serial int64, host string, expired bool) pair {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	now := time.Now()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	if host == "localhost" {
		leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else if ip := net.ParseIP(host); ip != nil {
		leaf.DNSNames = nil
		leaf.IPAddresses = []net.IP{ip}
	}
	if expired {
		leaf.NotBefore = now.Add(-2 * time.Hour)
		leaf.NotAfter = now.Add(-time.Hour)
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(err)
	}
	return pair{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private}))}
}

func main() {
	if err := json.NewEncoder(os.Stdout).Encode(map[string]pair{"first": certificate(1, "localhost", false), "second": certificate(2, "localhost", false), "wrong": certificate(3, "example.invalid", false), "expired": certificate(4, "localhost", true), "public": certificate(5, "8.8.8.8", false), "domain": certificate(6, "panel.example.test", false)}); err != nil {
		panic(err)
	}
}
