package tlstest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"

	"errors"
	"net"
	"time"
)

// NewKey returns a new rsa private key
func NewKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// CertTemplate returns a new generic template for an x509.Certificate
// which is set to use SHA256 and expire after an hour
func CertTemplate() (*x509.Certificate, error) {
	// generate a random serial number (a real cert authority would have some logic behind this)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.New("failed to generate serial number: " + err.Error())
	}

	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"Fly.io"}},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour), // valid for an hour
		BasicConstraintsValid: true,
	}
	return &tmpl, nil
}

func createCert(template, parent *x509.Certificate, pub interface{}, parentPriv interface{}) (*x509.Certificate, []byte, error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentPriv)
	if err != nil {
		return nil, nil, err
	}
	// parse the resulting certificate so we can use it again
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}
	// PEM encode the certificate (this is a standard TLS encoding)
	b := pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	certPEM := pem.EncodeToMemory(&b)
	return cert, certPEM, err
}

func createRootKeyWithCert() (rootKey *rsa.PrivateKey, rootCrt *x509.Certificate, rootCrtPEM []byte, err error) {
	rootKey, err = NewKey()
	if err != nil {
		return
	}

	rootKey, err = NewKey()
	if err != nil {
		return
	}

	crtTempl, err := CertTemplate()
	if err != nil {
		return
	}

	// describe what the certificate will be used for
	crtTempl.IsCA = true
	crtTempl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	crtTempl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	crtTempl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}

	rootCrt, rootCrtPEM, err = createCert(crtTempl, crtTempl, &rootKey.PublicKey, rootKey)
	return
}

func CreateRootCertKeyPEMPair() ([]byte, []byte, error) {
	rootKey, _, rootCrtPEM, err := createRootKeyWithCert()
	if err != nil {
		return nil, nil, err
	}

	// PEM encode the private key
	rootKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rootKey),
	})

	return rootCrtPEM, rootKeyPEM, nil
}

func CreateRootTLSCert() (*tls.Certificate, error) {
	rootCrtPEM, rootKeyPEM, err := CreateRootCertKeyPEMPair()
	if err != nil {
		return nil, err
	}

	crt, err := tls.X509KeyPair(rootCrtPEM, rootKeyPEM)
	if err != nil {
		return nil, err
	}
	return &crt, err
}

func CreateServerCertKeyPEMPairWithRootCert() (rootCertPEM []byte, servCertPEM []byte, servKeyPEM []byte, err error) {
	rootKey, rootCrt, rootCertPEM, err := createRootKeyWithCert()
	if err != nil {
		return nil, nil, nil, err
	}
	servKey, err := NewKey()
	if err != nil {
		return nil, nil, nil, err
	}

	servTemplate, err := CertTemplate()
	if err != nil {
		return nil, nil, nil, err
	}
	servTemplate.KeyUsage = x509.KeyUsageDigitalSignature
	servTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	servTemplate.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}

	_, servCertPEM, err = createCert(servTemplate, rootCrt, &servKey.PublicKey, rootKey)
	servKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(servKey),
	})
	return
}

func CreateServerClientTLSConfig() (serverConfig *tls.Config, clientConfig *tls.Config, err error) {
	rootCertPEM, servCertPEM, servKeyPEM, err := CreateServerCertKeyPEMPairWithRootCert()
	if err != nil {
		return
	}

	servTLSCert, err := tls.X509KeyPair(servCertPEM, servKeyPEM)
	if err != nil {
		return
	}

	serverConfig = &tls.Config{
		Certificates: []tls.Certificate{servTLSCert},
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(rootCertPEM)

	clientConfig = &tls.Config{
		RootCAs:    certPool,
		ServerName: "127.0.0.1",
	}
	return
}
