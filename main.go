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

	rootCaCertificate, rootCaPrivKey, err := makeRootCaCertificate()
	if err != nil {
		panic(err)
	}

	intCaCertificate, intCaPrivKey, err := makeIntCaCertificate(rootCaCertificate, rootCaPrivKey)
	if err != nil {
		panic(err)
	}

	serverCertificate, serverPrivKey, err := makeServerCertificate(intCaCertificate, intCaPrivKey)
	if err != nil {
		panic(err)
	}

	rootCaPEM, err := writeCertPEM(rootCaCertificate, "/tmp/capublic.pem")
	if err != nil {
		panic(err)
	}

	intCaPEM, err := writeCertPEM(intCaCertificate, "/tmp/intpublic.pem")
	if err != nil {
		panic(err)
	}

	_, err = writeCertPEM(serverCertificate, "/tmp/serverpublic.pem")
	if err != nil {
		panic(err)
	}

	err = writeKeyPEM(serverPrivKey, "/tmp/serverkey.pem")
	if err != nil {
		panic(err)
	}

	s := [][]byte{rootCaPEM.Bytes(), intCaPEM.Bytes()}
	err = os.WriteFile("/tmp/cabundle.pem", bytes.Join(s, []byte("\n")), 0644)
	if err != nil {
		panic(err)
	}

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

func makeServerCertificate(caCert []byte, caPrivKey *rsa.PrivateKey) ([]byte, *rsa.PrivateKey, error) {

	caCertTemplate, err := x509.ParseCertificate(caCert)
	if err != nil {
		return nil, nil, err
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

	// create our private and public key
	serverPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	// create the CA Certificate
	serverCertificate, err := x509.CreateCertificate(rand.Reader, serverCertTemplate, caCertTemplate, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	return serverCertificate, serverPrivKey, nil

}
