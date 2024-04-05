package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"
)

func main() {

	serverKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	chain, err := makeCertChain(serverKey.PublicKey)
	if err != nil {
		panic(err)
	}

	err = writePEMFiles(chain, serverKey)
	if err != nil {
		panic(err)
	}

}

func makeCertChain(serverKey rsa.PublicKey) (chain [][]byte, err error) {

	rootCa, rootCaKey, err := makeRootCaCertificate()
	if err != nil {
		return nil, err
	}

	intCa, intCaKey, err := makeIntCaCertificate(rootCa, rootCaKey)
	if err != nil {
		return nil, err
	}

	serverCert, err := makeServerCertificate(intCa, intCaKey, serverKey)
	if err != nil {
		return nil, err
	}

	return [][]byte{rootCa, intCa, serverCert}, nil

}

func writePEMFiles(chain [][]byte, key *rsa.PrivateKey) error {

	rootCaPEM, err := writeCertPEM(chain[0], "/tmp/capublic.pem")
	if err != nil {
		return (err)
	}

	intCaPEM, err := writeCertPEM(chain[1], "/tmp/intpublic.pem")
	if err != nil {
		return (err)
	}

	_, err = writeCertPEM(chain[2], "/tmp/serverpublic.pem")
	if err != nil {
		return (err)
	}

	err = writeKeyPEM(key, "/tmp/serverkey.pem")
	if err != nil {
		return (err)
	}

	s := [][]byte{rootCaPEM.Bytes(), intCaPEM.Bytes()}
	err = os.WriteFile("/tmp/cabundle.pem", bytes.Join(s, []byte("\n")), 0644)
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

func makeServerCertificate(caCert []byte, caPrivKey *rsa.PrivateKey, serverKey rsa.PublicKey) ([]byte, error) {

	caCertTemplate, err := x509.ParseCertificate(caCert)
	if err != nil {
		return nil, err
	}

	// Define CA certificate template
	serverCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName: "test.example.org",
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
