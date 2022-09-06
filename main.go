package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
)

// Read the key encryption key from a specified location
func GetKek(pathToKek string) *keyset.Handle {
	kekFile, err := os.Open(pathToKek)
	if err != nil {
		fmt.Println("Unable to read KEK", err)
		return nil
	}

	jsonReader := keyset.NewJSONReader(kekFile)

	kek, err := insecurecleartextkeyset.Read(jsonReader)
	if err != nil {
		fmt.Println("Unable to parse KEK", err)
		return nil
	}

	return kek
}

// Create a new data encryption key and encrypt it using the specified KEK
func CreateDek(kek *keyset.Handle) []byte {
	// generate a new DEK
	dek, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		fmt.Println("Unable to create DEK", err)
		return nil
	}

	// encrypt the DEK using the KEK
	return encryptDek(kek, dek)
}

// Encrypt the data encryption key using the specified KEK
func encryptDek(kek *keyset.Handle, dek *keyset.Handle) []byte {
	// create the AEAD primitive using the KEK
	aeadPrimitive, err := aead.New(kek)
	if err != nil {
		fmt.Println("Unable to create AEAD primitive from KEK", err)
		return nil
	}

	// Buffer to hold the encrypted bytes
	encryptedDek := &bytes.Buffer{}
	binaryWriter := keyset.NewBinaryWriter(encryptedDek)

	// Encrypt the DEK
	err = dek.Write(binaryWriter, aeadPrimitive)
	if err != nil {
		fmt.Println("Unable to encrypt DEK", err)
		return nil
	}

	// return the encrypted bytes
	return encryptedDek.Bytes()
}

// Decrypt the data encryption key using the specified KEK
func decryptDek(kek *keyset.Handle, encryptedDek []byte) *keyset.Handle {
	// create the AEAD primitive using the KEK
	aeadPrimitive, err := aead.New(kek)
	if err != nil {
		fmt.Println("Unable to create AEAD primitive from KEK", err)
		return nil
	}

	// Decrypt the DEK
	binaryReader := keyset.NewBinaryReader(bytes.NewBuffer(encryptedDek))
	dek, err := keyset.Read(binaryReader, aeadPrimitive)
	if err != nil {
		fmt.Println("Unable to decrypt the DEK", err)
		return nil
	}

	return dek
}

// Encrypt the plaintext
func Encrypt(data []byte, kek *keyset.Handle, encryptedDek []byte) []byte {
	// Decrypt the DEK using the KEK
	dek := decryptDek(kek, encryptedDek)

	// Get the AEAD primitive from the DEK
	aeadPrimitive, err := aead.New(dek)
	if err != nil {
		fmt.Println("Unable to create AEAD primitive from DEK", err)
		return nil
	}

	// Encrypt the data
	encryptedBytes, err := aeadPrimitive.Encrypt(data, nil)
	if err != nil {
		fmt.Println("Unable to encrypt the data using DEK", err)
		return nil
	}

	// throw away the DEK
	aeadPrimitive = nil
	dek = nil

	return encryptedBytes
}

// Decrypt the ciphertext
func Decrypt(encryptedBytes []byte, kek *keyset.Handle, encryptedDek []byte) []byte {
	// Decrypt the DEK using the KEK
	dek := decryptDek(kek, encryptedDek)

	// Get the AEAD primitive from the DEK
	aeadPrimitive, err := aead.New(dek)
	if err != nil {
		fmt.Println("Unable to create AEAD primitive from DEK", err)
		return nil
	}

	// Decrypt the data
	decryptedBytes, err := aeadPrimitive.Decrypt(encryptedBytes, nil)
	if err != nil {
		fmt.Println("Unable to decrypt the data using DEK", err)
		return nil
	}

	// throw away the DEK
	aeadPrimitive = nil
	dek = nil

	return decryptedBytes
}

func main() {
	kekPath := os.Args[1]

	plainText := "The quick brown fox jumps over the lazy dog"
	fmt.Println("This is the plain text to encrypt:", plainText)

	// Assuming we fetch the KEK securely
	// tinkey create-keyset --key-template AES128_GCM --out kek.json
	kek := GetKek(kekPath)
	fmt.Println("Fetched the KEK")

	encryptedDek := CreateDek(kek)
	fmt.Println("Generated a new encrypted DEK", base64.StdEncoding.EncodeToString(encryptedDek))

	encryptedBytes := Encrypt([]byte(plainText), kek, encryptedDek)
	fmt.Println("Encrypted plain text to:", base64.StdEncoding.EncodeToString(encryptedBytes))

	decryptedBytes := Decrypt(encryptedBytes, kek, encryptedDek)
	fmt.Println("Decrypted cipher text to:", string(decryptedBytes))
}
