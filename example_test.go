package paillier_test

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/roasbeef/go-go-gadget-paillier"
)

// This example demonstrates basic usage of this library.
// Features shown:
//   * Encrypt/Decrypt
//   * Homomorphic cipher text addition
//   * Homomorphic addition with constant
//   * Homomorphic multiplication with constant
func main() {
	// Generate a 128-bit private key.
	privKey, err := paillier.GenerateKey(rand.Reader, 128)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Encrypt the number "15".
	m15 := new(big.Int).SetInt64(15)
	c15, err := paillier.Encrypt(&privKey.PublicKey, m15.Bytes())
	if err != nil {
		fmt.Println(err)
		return
	}

	// Decrypt the number "15".
	d, err := paillier.Decrypt(privKey, c15)
	if err != nil {
		fmt.Println(err)
		return
	}
	plainText := new(big.Int).SetBytes(d)
	fmt.Println("Decryption Result of 15: ", plainText.String())

	// Now for the fun stuff.
	// Encrypt the number "20".
	m20 := new(big.Int).SetInt64(20)
	c20, err := paillier.Encrypt(&privKey.PublicKey, m20.Bytes())
	if err != nil {
		fmt.Println(err)
		return
	}

	// Add the encrypted integers 15 and 20 together.
	plusM16M20 := paillier.AddCipher(&privKey.PublicKey, c15, c20)
	decryptedAddition, err := paillier.Decrypt(privKey, plusM16M20)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Result of 15+20 after decryption: ",
		new(big.Int).SetBytes(decryptedAddition).String()) // 35

	// Add the encrypted integer 15 to plaintext constant 10.
	plusE15and10 := paillier.Add(&privKey.PublicKey, c15, new(big.Int).SetInt64(10).Bytes())
	decryptedAddition, err = paillier.Decrypt(privKey, plusE15and10)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Result of 15+10 after decryption: ",
		new(big.Int).SetBytes(decryptedAddition).String()) // 25

	// Multiply the encrypted integer 15 by the plaintext constant 10.
	mulE15and10 := paillier.Mul(&privKey.PublicKey, c15, new(big.Int).SetInt64(10).Bytes())
	decryptedMul, err := paillier.Decrypt(privKey, mulE15and10)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Result of 15*10 after decryption: ",
		new(big.Int).SetBytes(decryptedMul).String()) // 150
}
