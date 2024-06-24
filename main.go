package main

import (
	"fmt"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
	"log"
	"os"
)

func main() {
	GenerateKeys()
	inputFile := ReadFile("./input/test.txt")
	EncryptFile(inputFile)

	encryptedFile := ReadFile("./output/encrypt/message.txt.gpg")
	DecryptFile(encryptedFile)
}

func GenerateKeys() {
	const (
		name    = "DEV"
		email   = "dev@test.com"
		rsaBits = 2048
	)
	var passphrase = []byte("secret")

	rsaKey, _ := helper.GenerateKey(name, email, passphrase, "rsa", rsaBits)
	privateKeyObj, err := crypto.NewKeyFromArmored(rsaKey)
	if err != nil {
		log.Fatal(err)
		return
	}
	publicKeyObj, err := privateKeyObj.GetArmoredPublicKey()
	if err != nil {
		log.Fatal(err)
		return
	}

	if err := SaveFile("./keys/private_key.asc", []byte(rsaKey)); err != nil {
		log.Fatal(err)
		return
	}

	if err := SaveFile("./keys/public_key.asc", []byte(publicKeyObj)); err != nil {
		log.Fatal(err)
		return
	}

	fmt.Println("Llaves generadas con exito !!")
}

func EncryptFile(inputFile string) {
	publicKey := ReadFile("./keys/public_key.asc")
	encrypted, err := helper.EncryptBinaryMessageArmored(publicKey, []byte(inputFile))
	if err != nil {
		log.Fatal(err)
		return
	}

	if err := SaveFile("./output/encrypt/message.txt.gpg", []byte(encrypted)); err != nil {
		log.Fatal(err)
		return
	}

	fmt.Println("Mensaje cifrado con exito !!")
}

func DecryptFile(encryptedFile string) {
	privateKey := ReadFile("./keys/private_key.asc")
	decrypted, err := helper.DecryptMessageArmored(privateKey, []byte("secret"), encryptedFile)
	if err != nil {
		log.Fatal(err)
		return
	}

	if err := SaveFile("./output/decrypt/message.txt", []byte(decrypted)); err != nil {
		log.Fatal(err)
		return
	}

	fmt.Println("Mensaje decifrado con exito !!")
}

func ReadFile(path string) string {
	fileBytes, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	return string(fileBytes)
}

func SaveFile(filename string, data []byte) error {
	err := os.WriteFile(filename, data, 0644)
	if err != nil {
		return err
	}

	return nil
}
