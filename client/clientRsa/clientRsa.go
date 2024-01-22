package clientRsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

var readBuff = make([]byte, 4096)

func GenerateRsa(user string) (crypto.PublicKey, *rsa.PrivateKey) {
	fileNamePriv := fmt.Sprintf("./%s.rsa", user)
	fileNamePub := fmt.Sprintf("./%s.rsa.pub", user)
	bitSize := 4096

	key, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		log.Fatal(err)
	}

	pub := key.Public()

	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)

	pubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(pub.(*rsa.PublicKey)),
		},
	)

	f1, err := os.Create(fileNamePriv)
	if err != nil {
		log.Fatal(err)
	}

	f2, err := os.Create(fileNamePub)
	if err != nil {
		log.Fatal(err)
	}

	// remember to close the file
	defer f1.Close()
	defer f2.Close()

	_, err = f1.WriteString(string(keyPEM))
	if err != nil {
		log.Fatal(err)
	}

	_, err = f2.WriteString(string(pubPEM))

	return pubPEM, key
}

func ReadPrivateKeyFromFile(file string) *rsa.PrivateKey {
	// Read the private key file
	if _, err := os.Stat(file); err == nil {
		// file exists
		f, err := os.Open(file)
		if err != nil {
			log.Fatal(err)
		}

		defer f.Close()

		n, err := f.Read(readBuff)
		if err != nil {
			log.Fatal(err)
		}
		block, _ := pem.Decode([]byte(readBuff[:n]))
		if block == nil {
			log.Fatal("failed to decode PEM block from private key file")
		}

		// Parse the DER-encoded private key
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}

		return privateKey
	} else {
		log.Fatal("error with getting rsa")
	}
	return nil
}
