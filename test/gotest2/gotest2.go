package main

import (
	"crypto/mlkem"
	"fmt"
	"os"
	"runtime/secret"
)

func main() {

	// Use runtime/secret to zeroize memory: https://pkg.go.dev/runtime/secret

	secret.Do(func() {
		// Key generation and save public key
		dk, err := mlkem.GenerateKey768()
		if err != nil {
			fmt.Println("GenerateKey failed")
		}
		ek := dk.EncapsulationKey()
		os.WriteFile("pub.bin", ek.Bytes(), 0644)

		// Encapsulation and save ciphertext
		_, ct := ek.Encapsulate()
		os.WriteFile("ct.bin", ct, 0644)
	})

	// Pause
	fmt.Scanln()
}
