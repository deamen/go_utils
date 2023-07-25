package options

import (
	"flag"
	"fmt"

	"github.com/golang/glog"
)

type Options struct {
	InputFile  string
	OutputFile string
	Key        string
	Encryption bool
	Decryption bool
}

type WrongArgumentsError string

func (wae WrongArgumentsError) Error() string {
	return fmt.Sprintf("Wrong application arguments: %s\n", string(wae))
}

func (options *Options) Validate() (err error) {
	glog.Infoln("Parsing arguments...")
	if !flag.Parsed() {
		err = WrongArgumentsError("Use flag.Parse first()")
		return
	}

	if options.Encryption == options.Decryption {
		err = WrongArgumentsError("You must specify encryption or decryption operation.")
		return
	}

	if options.InputFile == "" {
		err = WrongArgumentsError("You must specify an input file.")
		return
	}

	if options.OutputFile == "" {
		options.OutputFile = options.OutputFile + "_output"
	}

	err = nil
	return
}
