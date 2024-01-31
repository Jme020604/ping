// this part of the program contains all the diffie hellmann key exchange features
package diffie

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// this function generates the prime and teh ground number
func GeneratePrime() (*big.Int, *big.Int, error) {
	bitSize := 2048

	prime, err := rand.Prime(rand.Reader, bitSize)
	if err != nil {
		return nil, nil, err
	}

	g := big.NewInt(2)

	return prime, g, nil
}

// this function generates the private key using the prime
func GeneratePrivateKey(p *big.Int) *big.Int {
	// Generate a private key in the range [2, p-2]
	max := new(big.Int).Sub(p, big.NewInt(2))
	privateKey, err := rand.Int(rand.Reader, max)
	if err != nil {
		fmt.Println("Error generating private key:", err)
		return nil
	}

	// Add 2 to make sure the private key is in the range [2, p-1]
	privateKey.Add(privateKey, big.NewInt(2))

	return privateKey
}

// this function generate the private key
func GeneratePublicKey(privateKey, p, g *big.Int) *big.Int {
	publicKey := new(big.Int).Exp(g, privateKey, p)
	return publicKey
}

// this function calculates the shared secret
func CalcShareKey(otherPublicKey, privateKey, prime *big.Int) *big.Int {
	result := new(big.Int).Exp(otherPublicKey, privateKey, prime)

	return result
}
