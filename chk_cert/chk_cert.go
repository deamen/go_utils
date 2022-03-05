/*
Check certificate against the days to expire provided by the user
Assume the input file contains certificates chain and private keys
*/

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"text/tabwriter"
	"time"

	"golang.org/x/crypto/pkcs12"
)

var availCmds = []string{
	"pkcs12",
	"x509",
}

var inFile string
var warnDays int
var critDays int
var rc = 3
var rm = "Unknown - Check stderr"

func prtCmds() {
	var b bytes.Buffer
	tw := tabwriter.NewWriter(&b, 0, 8, 4, ' ', 0)

	fmt.Fprintf(tw, "Usage: chk_cert <command> [args]\n\n")
	fmt.Fprintf(tw, "Available commands:\n")
	for _, v := range availCmds {
		fmt.Fprintf(tw, "\t%s\n", v)
	}

	tw.Flush()
	fmt.Println(b.String())
}

func chkCertExpDays(cert x509.Certificate) int {
	tNow := time.Now()
	hrsExp := cert.NotAfter.Sub(tNow).Hours()

	return int(hrsExp / 24)
}

func getInFile(inFile string) []byte {
	rawFile, err := ioutil.ReadFile(inFile)

	if err != nil {
		panic(err)
	}
	return rawFile
}

func getCertFromP12(rawFile []byte, password string) (*tls.Certificate, error) {
	pemBlocks, error := pkcs12.ToPEM(rawFile, password)

	if error != nil {
		panic(error)
	}
	var cert tls.Certificate
	for _, block := range pemBlocks {
		//b, _ := pem.Decode(block.Bytes)
		if block.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, block.Bytes)
		} else {
			fmt.Println("Private key")
		}
	}

	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("no certificate found in \"%s\"", inFile)
	} else if cert.PrivateKey != nil {
		return nil, fmt.Errorf("private key found in \"%s\"", inFile)
	}

	return &cert, nil
}

func getCertAndKey(rawFile []byte) (*tls.Certificate, error) {

	var cert tls.Certificate
	for {
		block, rest := pem.Decode(rawFile)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, block.Bytes)
		} else {
			fmt.Println("Private key")
		}
		rawFile = rest
	}

	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("no certificate found in \"%s\"", inFile)
	} else if cert.PrivateKey != nil {
		return nil, fmt.Errorf("private key found in \"%s\"", inFile)
	}

	return &cert, nil
}

func getX509Cert(tlsCert *tls.Certificate) (*x509.Certificate, error) {
	x509Cert, error := x509.ParseCertificate(tlsCert.Certificate[0])
	if error != nil {
		fmt.Println(error)
	}
	return x509Cert, error
}

func main() {
	pkcs12Cmd := flag.NewFlagSet("pkcs12", flag.ExitOnError)
	pkcs12In := pkcs12Cmd.String("in", "", "The PKCS12 bundle")
	pkcs12Warn := pkcs12Cmd.Int("warn", 30, "The warning days")
	pkcs12Crit := pkcs12Cmd.Int("crit", 15, "The critical days")
	pkcs12Pass := pkcs12Cmd.String("pass", "", "The password")
	pkcs12NoPass := pkcs12Cmd.Bool("nopass", false, "Indicate the file is not protected by password")
	pkcs12File := false

	x509Cmd := flag.NewFlagSet("x509", flag.ExitOnError)
	x509In := x509Cmd.String("in", "", "The x509 cert")
	x509Warn := x509Cmd.Int("warn", 30, "The warning days")
	x509Crit := x509Cmd.Int("crit", 15, "The critical days")
	x509File := false

	if len(os.Args) < 2 {
		prtCmds()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "pkcs12":
		pkcs12Cmd.Parse(os.Args[2:])
		if *pkcs12In == "" {
			fmt.Println("expected input file")
			os.Exit(1)
		}
		inFile = *pkcs12In
		if !*pkcs12NoPass {
			if *pkcs12Pass == "" {
				fmt.Println("expected password")
				os.Exit(1)
			}
		}

		warnDays = *pkcs12Warn
		critDays = *pkcs12Crit

		if *pkcs12Warn <= *pkcs12Crit {
			fmt.Println("Critical days is less than warning days")
			os.Exit(1)
		}
		pkcs12File = true
	case "x509":
		x509Cmd.Parse(os.Args[2:])
		if *x509In == "" {
			fmt.Println("expected input file")
		}
		inFile = *x509In

		if *x509Warn <= *x509Crit {
			fmt.Println("Critical days is less than warning days")
			os.Exit(1)
		}
		warnDays = *x509Warn
		critDays = *x509Crit
		x509File = true

	default:
		prtCmds()
		os.Exit(1)
	}

	rawFile := getInFile(inFile)
	var tlsCert *tls.Certificate

	if pkcs12File {
		tlsCert, _ = getCertFromP12(rawFile, *pkcs12Pass)
	} else if x509File {
		tlsCert, _ = getCertAndKey(rawFile)
	}
	x509Cert, error := getX509Cert(tlsCert)
	if error != nil {
		fmt.Println(error)
	}

	daysLeft := int(chkCertExpDays(*x509Cert))

	if daysLeft <= critDays {
		rc = 2
		rm = fmt.Sprintf("Critical - Exipres in %d days", daysLeft)
	} else if daysLeft <= warnDays && daysLeft > critDays {
		rc = 1
		rm = fmt.Sprintf("Warning - Exipres in %d days", daysLeft)
	}

	if daysLeft > warnDays {
		rc = 0
		rm = fmt.Sprintf("OK - Exipres in %d days", daysLeft)
	}

	fmt.Println(rm)
	os.Exit(rc)
}
