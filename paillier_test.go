package paillier_test

import (
	"crypto/rand"

	"github.com/roasbeef/go-go-gadget-paillier"

	"math/big"
	"testing"
)

func TestCorrectness(t *testing.T) {
	// Generate a 128-bit private key.
	privKey, err := paillier.GenerateKey(rand.Reader, 128)
	if err != nil {
		t.Fatalf("Unable to generate private key: ", err)
	}

	// Encrypt the integer 15.
	m := new(big.Int).SetInt64(15)
	c, err := paillier.Encrypt(&privKey.PublicKey, m.Bytes())
	if err != nil {
		t.Fatalf("Unable to encrypt plain text: ", err)
	}

	// Now decrypt the cipher text. Should come back out to 15.
	d, err := paillier.Decrypt(privKey, c)
	if err != nil {
		t.Fatalf("Unable to decrypt cipher text: ", err)
	}
	originalInt := new(big.Int).SetBytes(d)
	if originalInt.Cmp(m) != 0 { // originalInt != 15
		t.Fatalf("Scheme is not correct. Got %v back should've got %v",
			originalInt.String(), m.String())
	}
}

func TestHomomorphicCipherTextAddition(t *testing.T) {
	// Generate a 128-bit private key.
	privKey, err := paillier.GenerateKey(rand.Reader, 128)
	if err != nil {
		t.Fatalf("Unable to generate private key: ", err)
	}

	// Encrypt the integer 15.
	m15 := new(big.Int).SetInt64(15)
	c15, err := paillier.Encrypt(&privKey.PublicKey, m15.Bytes())
	if err != nil {
		t.Fatalf("Unable to encrypt plain text: ", err)
	}

	// Encrypt the integer 20.
	m20 := new(big.Int).SetInt64(20)
	c20, err := paillier.Encrypt(&privKey.PublicKey, m20.Bytes())
	if err != nil {
		t.Fatalf("Unable to encrypt plain text: ", err)
	}

	// Now homomorphically add the encrypted integers.
	addedCiphers := paillier.AddCipher(&privKey.PublicKey, c15, c20)

	// When decrypted, the result should be 15+20 = 35
	plaintext, err := paillier.Decrypt(privKey, addedCiphers)
	if err != nil {
		t.Fatalf("Unable to decrypted cipher text: ", err)
	}
	decryptedInt := new(big.Int).SetBytes(plaintext)
	if decryptedInt.Cmp(new(big.Int).SetInt64(35)) != 0 {
		t.Fatalf("Incorrect. Plaintext decrypted to %v should be %v",
			decryptedInt.String(), 35)
	}
}

func TestHomomorphicConstantAddition(t *testing.T) {
	// Generate a 128-bit private key.
	privKey, err := paillier.GenerateKey(rand.Reader, 128)
	if err != nil {
		t.Fatalf("Unable to generate private key: ", err)
	}

	// Encrypt the integer 15.
	m15 := new(big.Int).SetInt64(15)
	c15, err := paillier.Encrypt(&privKey.PublicKey, m15.Bytes())
	if err != nil {
		t.Fatalf("Unable to encrypt plain text: ", err)
	}

	// Attempt to add the plaintext constant "10" to our encrypted integer
	// "15".
	ten := new(big.Int).SetInt64(10)
	encryptedAdd := paillier.Add(&privKey.PublicKey, c15, ten.Bytes())
	plainText, err := paillier.Decrypt(privKey, encryptedAdd)
	if err != nil {
		t.Fatalf("Unable to decrypt cipher text: ", err)
	}
	decryptedInt := new(big.Int).SetBytes(plainText)

	// When decrypted, the result should be 15+10 = 25
	if decryptedInt.Cmp(new(big.Int).SetInt64(25)) != 0 {
		t.Fatalf("Incorrect. Plaintext decrypted to %v should be %v",
			decryptedInt.String(), 25)
	}

}

func TestHomomorphicConstantMultiplication(t *testing.T) {
	// Generate a 128-bit private key.
	privKey, err := paillier.GenerateKey(rand.Reader, 128)
	if err != nil {
		t.Fatalf("Unable to generate private key: ", err)
	}

	// Encrypt the integer 15.
	m15 := new(big.Int).SetInt64(15)
	c15, err := paillier.Encrypt(&privKey.PublicKey, m15.Bytes())
	if err != nil {
		t.Fatalf("Unable to encrypt plain text: ", err)
	}

	// Attempt to multiply our encrypted integer
	ten := new(big.Int).SetInt64(10)
	encryptedAdd := paillier.Mul(&privKey.PublicKey, c15, ten.Bytes())
	plainText, err := paillier.Decrypt(privKey, encryptedAdd)
	if err != nil {
		t.Fatalf("Unable to decrypt cipher text: ", err)
	}
	decryptedInt := new(big.Int).SetBytes(plainText)

	// When decrypted, the result should be 15*10 = 150
	if decryptedInt.Cmp(new(big.Int).SetInt64(150)) != 0 {
		t.Fatalf("Incorrect. Plaintext decrypted to %v should be %v",
			decryptedInt.String(), 150)
	}
}
