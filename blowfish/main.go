package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/deamen/go_utils/blowfish/cipherkey"
	"github.com/deamen/go_utils/blowfish/files"
	"github.com/deamen/go_utils/blowfish/options"

	"github.com/golang/glog"
)

var pars options.Options

func init() {
	flag.BoolVar(&pars.Encryption, "encrypt", false, "Encrypt a file.")
	flag.BoolVar(&pars.Decryption, "decrypt", false, "Decrypt a file.")
	flag.StringVar(&pars.InputFile, "input", "", "Input file.")
	flag.StringVar(&pars.OutputFile, "output", "", "Output file.")
	flag.StringVar(&pars.Key, "key", "", "Key path in Vault.")
}

func main() {
	flag.Parse()

	if err := pars.Validate(); err != nil {
		glog.Errorln(err)
		return
	}

	glog.Infof("Program arguments: %v\n", pars)

	key, err := cipherkey.GetSecretWithAppRole(pars.Key)
	if err != nil {
		glog.Errorln(err.Error())
		return
	}

	inputFile, err := os.Open(pars.InputFile)
	if err != nil {
		glog.Infof("Error: %v", err)
		return
	}
	defer inputFile.Close()

	outputFile, err := os.Create(pars.OutputFile)
	if err != nil {
		glog.Infof("Error: %v", err)
		return
	}
	defer outputFile.Close()

	var errOperation error
	if pars.Encryption {
		fmt.Println("Encrypting")
		errOperation = files.EncryptFile(inputFile, outputFile, []byte(key))
	} else {
		fmt.Println("Decrypting")
		errOperation = files.DecryptFile(inputFile, outputFile, []byte(key))

	}

	if errOperation != nil {
		glog.Errorf("Error: %v", errOperation)
		return
	}

}
