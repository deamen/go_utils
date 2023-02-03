package main

import (
	"flag"
	"fmt"
	"os"

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
	flag.StringVar(&pars.KeyFile, "key", "", "Key file.")
}

func main() {
	flag.Parse()

	if err := pars.Validate(); err != "" {
		glog.Errorln(err)
		return
	}

	glog.Infof("Program arguments: %v\n", pars)

	key, err := os.ReadFile(pars.KeyFile)
	if err != nil {
		glog.Errorln(err.Error())
		return
	}

	inputFile, err := os.Open(pars.InputFile)
	if err != nil {
		glog.Infof("Error: %v", err)
		return
	}

	outputFile, err := os.Create(pars.OutputFile)
	if err != nil {
		glog.Infof("Error: %v", err)
		return
	}

	var errOperation error
	if pars.Encryption {
		fmt.Printf("Encrypting")
		errOperation = files.EncryptFile(inputFile, outputFile, key)
	} else {
		fmt.Printf("Decrypting")
		errOperation = files.DecryptFile(inputFile, outputFile, key)

	}

	if errOperation != nil {
		glog.Errorf("Error: %v", errOperation)
		return
	}

	inputFile.Close()
	outputFile.Close()
}
