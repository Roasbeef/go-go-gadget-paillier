# go-go-gadget-paillier
A Go implementation of the partially homomorphic [Paillier Cryptosystem](http://en.wikipedia.org/wiki/Paillier_cryptosystem).

![Inspector Paillier](https://raw.githubusercontent.com/Roasbeef/go-go-gadget-paillier/master/imgs/Inspector-gadget.jpg?token=AA87LnAHpds9_MUKhbsCKXhn-u47CkJ4ks5U6_XvwA%3D%3D "Inspector Paillier")

## Explanation
*Homomorphic* cryptosystems are a family of cryptosystems that allow computations to be performed on generated ciphertexts. The general idea is that: within one of these systems, one is able to perform certain computations on a chiper text, which when decrypted reflects those operations on the corresponding plaintext. 

Cryptosystems from this family that support **arbitary** computations are known as *Fully* Homomorphic Cryptosystems (FHE). This powerful property would allow for the creation extremely useful systems whose functionality operates on inputs which are entirely encrypted, subsequently producing encrypted output. With the ability to perform arbitary computation on encrypted data, one could outsource sensitive private data to third-parties who are then able to perform useful operations without ever decrypting the data. Applications of this technology are extremley wide reaching, and could be applied to services such as:  Search Engines, Cloud Computing Providers, E-Mail spam detection, etc. 

However, most FHE systems are too inefficient for practical use, and are an on-going research area in the field of Cryptography. 

Instead, this package contains an implementation of a *Partially* Homomorphic Cryptosystem. Partially homomorphic encryption instead only supports a subset of operations on ciphertexts. Examples of such systems are those that support *addition* or *multiplication* on ciphertexts. 

The **Paillier Cryptosystem** is an additive cryptosystem. This means that given two ciphertexts, one can perform operations equivalent to adding the respective plaintexts. Additionally, Paillier Cryptosystem supports further computations:
   * Encrypted integers can be added together
   * Encrypted integers can be multiplied by an unencrypted integer
   * Encrypted integers and unencrypted integers can be added together

## Example Usage
```go

// Generate a 128-bit private key.
privKey, _ := paillier.GenerateKey(rand.Reader, 128)

// Encrypt the number "15".
m15 := new(big.Int).SetInt64(15)
c15, _ := paillier.Encrypt(&privKey.PublicKey, m15.Bytes())

// Decrypt the number "15".
d, _ := paillier.Decrypt(privKey, c15)
plainText := new(big.Int).SetBytes(d)
fmt.Println("Decryption Result of 15: ", plainText.String()) // 15

// Now for the fun stuff.
        
// Encrypt the number "20".
m20 := new(big.Int).SetInt64(20)
c20, _ := paillier.Encrypt(&privKey.PublicKey, m20.Bytes())

// Add the encrypted integers 15 and 20 together.
plusM15M20 := paillier.AddCipher(&privKey.PublicKey, c15, c20)
decryptedAddition, _ := paillier.Decrypt(privKey, plusM15M20)
fmt.Println("Result of 15+20 after decryption: ",
        new(big.Int).SetBytes(decryptedAddition).String()) // 35!

// Add the encrypted integer 15 to plaintext constant 10.
plusE15and10 := paillier.Add(&privKey.PublicKey, c15, new(big.Int).SetInt64(10).Bytes())
decryptedAddition, _ = paillier.Decrypt(privKey, plusE15and10)
fmt.Println("Result of 15+10 after decryption: ",
        new(big.Int).SetBytes(decryptedAddition).String()) // 25!

// Multiply the encrypted integer 15 by the plaintext constant 10.
mulE15and10 := paillier.Mul(&privKey.PublicKey, c15, new(big.Int).SetInt64(10).Bytes())
decryptedMul, _ := paillier.Decrypt(privKey, mulE15and10)
fmt.Println("Result of 15*10 after decryption: ",
        new(big.Int).SetBytes(decryptedMul).String()) // 150!
```

## Installation
```bash
$ go get github.com/roasbeef/go-go-gadget-paillier
```

## Warning
This library was created primarily for education purposes, with future application for a course project. You should **NOT USE THIS CODE IN PRODUCTION SYSTEMS**. 

## Benchmarks
```bash
$ go test -timeout 5h -bench=. -benchtime=1m
```
