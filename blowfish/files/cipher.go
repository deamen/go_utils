package files

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/blowfish"

	"github.com/andreburgaud/crypt2go/ecb"
	"github.com/andreburgaud/crypt2go/padding"
)

func EncryptFile(inputFile, outputFile *os.File, key []byte) error {

	writer := bufio.NewWriter(outputFile)
	plainText, err := io.ReadAll(inputFile)
	if err != nil {
		fmt.Printf("%s\n", err)
		//return
	}

	cipher, err := blowfish.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	mode := ecb.NewECBEncrypter(cipher)
	padder := padding.NewPkcs5Padding()
	plainText, err = padder.Pad(plainText) // pad last block of plaintext if block size less than block cipher size
	if err != nil {
		panic(err.Error())
	}
	cipherText := make([]byte, len(plainText))
	mode.CryptBlocks(cipherText, plainText)

	_, err = writer.Write(cipherText)
	if err != nil {
		fmt.Printf("%s\n", err)
	}

	writer.Flush()

	return nil
}

func DecryptFile(inputFile, outputFile *os.File, key []byte) error {

	writer := bufio.NewWriter(outputFile)

	cipherText, err := io.ReadAll(inputFile)
	if err != nil {
		fmt.Printf("%s\n", err)
		//return
	}

	cipher, err := blowfish.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	mode := ecb.NewECBDecrypter(cipher)
	plainText := make([]byte, len(cipherText))
	mode.CryptBlocks(plainText, cipherText)
	padder := padding.NewPkcs5Padding()
	plainText, err = padder.Unpad(plainText) // pad last block of plaintext if block size less than block cipher size
	if err != nil {
		panic(err.Error())
	}

	_, err = writer.Write(plainText)
	if err != nil {
		fmt.Printf("%s\n", err)
	}

	writer.Flush()

	return nil
}
