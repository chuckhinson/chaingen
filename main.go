package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"math/big"
	"os"
	"regexp"
	"strings"
	"time"
)

func main() {

	var serverName string
	flag.StringVar(&serverName, "host", "test.example.com", "hostname for certificate")
	flag.Parse()

	if !isValidDomain(serverName) {
		panic("host name is not a valid name")
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	chain, err := makeCertChain(serverName, serverKey.PublicKey)
	if err != nil {
		panic(err)
	}

	prefix := strings.ToLower(serverName)
	prefix = strings.Replace(serverName, "*", "STAR", 1)
	prefix = strings.ReplaceAll(prefix, ".", "_")
	err = writePEMFiles(chain, serverKey, prefix)
	if err != nil {
		panic(err)
	}

}

// isValidDomain checks for valid domain name, including wildcard domains
func isValidDomain(domain string) bool {
	regex := `^(\*\.)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
	match, _ := regexp.MatchString(regex, domain)
	return match
}

func makeCertChain(serverName string, serverKey rsa.PublicKey) (chain [][]byte, err error) {

	rootCa, rootCaKey, err := makeRootCaCertificate()
	if err != nil {
		return nil, err
	}

	intCa, intCaKey, err := makeIntCaCertificate(rootCa, rootCaKey)
	if err != nil {
		return nil, err
	}

	serverCert, err := makeServerCertificate(intCa, intCaKey, serverName, serverKey)
	if err != nil {
		return nil, err
	}

	return [][]byte{rootCa, intCa, serverCert}, nil

}

func writePEMFiles(chain [][]byte, key *rsa.PrivateKey, prefix string) error {

	rootCaPEM, err := writeCertPEM(chain[0], "capublic.pem")
	if err != nil {
		return (err)
	}

	intCaPEM, err := writeCertPEM(chain[1], "intpublic.pem")
	if err != nil {
		return (err)
	}

	_, err = writeCertPEM(chain[2], prefix+".crt")
	if err != nil {
		return (err)
	}

	err = writeKeyPEM(key, prefix+".key")
	if err != nil {
		return (err)
	}

	s := [][]byte{rootCaPEM.Bytes(), intCaPEM.Bytes()}
	err = os.WriteFile(prefix+".ca-bundle", bytes.Join(s, []byte("\n")), 0644)
	if err != nil {
		panic(err)
	}

	return nil
}

func writeKeyPEM(privateKey *rsa.PrivateKey, filename string) error {
	privateKeyPEM := new(bytes.Buffer)
	pem.Encode(privateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	err := os.WriteFile(filename, privateKeyPEM.Bytes(), 0644)
	if err != nil {
		panic(err)
	}
	return err
}

func writeCertPEM(cert []byte, filename string) (*bytes.Buffer, error) {
	// pem encode
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})

	err := os.WriteFile(filename, certPEM.Bytes(), 0644)

	return certPEM, err
}

func makeRootCaCertificate() ([]byte, *rsa.PrivateKey, error) {

	// Define CA certificate template
	rootCaTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName:   "Example Dev Root CA",
			Organization: []string{"Example"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create our private and public key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	// create the CA Certificate
	caCertificate, err := x509.CreateCertificate(rand.Reader, rootCaTemplate, rootCaTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	return caCertificate, caPrivKey, nil

}

func makeIntCaCertificate(rootCaCert []byte, rootCaPrivKey *rsa.PrivateKey) ([]byte, *rsa.PrivateKey, error) {

	rootCaCertTemplate, err := x509.ParseCertificate(rootCaCert)
	if err != nil {
		return nil, nil, err
	}

	// Define CA certificate template
	intCaCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName:   "Example Dev Intermediate CA",
			Organization: []string{"Example"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create our private and public key
	intCaPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	// create the CA Certificate
	intCaCertificate, err := x509.CreateCertificate(rand.Reader, intCaCertTemplate, rootCaCertTemplate, &intCaPrivKey.PublicKey, rootCaPrivKey)
	if err != nil {
		return nil, nil, err
	}

	return intCaCertificate, intCaPrivKey, nil

}

func makeServerCertificate(caCert []byte, caPrivKey *rsa.PrivateKey, serverName string, serverKey rsa.PublicKey) ([]byte, error) {

	caCertTemplate, err := x509.ParseCertificate(caCert)
	if err != nil {
		return nil, err
	}

	// Define CA certificate template
	serverCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName: serverName,
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature}

	// create the CA Certificate
	serverCertificate, err := x509.CreateCertificate(rand.Reader, serverCertTemplate, caCertTemplate, &serverKey, caPrivKey)
	if err != nil {
		return nil, err
	}

	return serverCertificate, nil

}
