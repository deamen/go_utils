/*
Check certificate against the days to expire provided by the user
Assumptions:
  1. PKCS12 bundle contains full chain certs and key, one pair
  2. PKCS8 bundle in pem format contains full chain certs and key, one pair
  3. PKCS8 cert in der format contains full chain certs
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

var version string
var build string
var inFile string
var warnDays int
var critDays int
var rc = 3
var rm = "Unknown - Check stderr"

func prtCmds() {
	var b bytes.Buffer
	tw := tabwriter.NewWriter(&b, 0, 8, 4, ' ', 0)

	fmt.Fprintf(tw, "Usage: chk_cert <command> [args]\n")
	fmt.Fprintf(tw, "Version: %s-%s\n\n", version, build)

	fmt.Fprintf(tw, "Available commands:\n")
	for _, v := range availCmds {
		fmt.Fprintf(tw, "\t%s\n", v)
	}

	tw.Flush()
	fmt.Println(b.String())
}

func exitWithMsg(rc int, rm string) {
	fmt.Println(rm)
	os.Exit(rc)
}

func chkCertExpDays(cert x509.Certificate) int {
	tNow := time.Now()
	hrsExp := cert.NotAfter.Sub(tNow).Hours()

	return int(hrsExp / 24)
}

func getInFile(inFile string) []byte {
	rawFile, err := ioutil.ReadFile(inFile)

	if err != nil {
		rc = 3
		rm = fmt.Sprintf("Unknown - %s", err)

		exitWithMsg(rc, rm)
	}

	return rawFile
}

func getCertFromP12(rawFile []byte, password string) *tls.Certificate {
	pemBlocks, err := pkcs12.ToPEM(rawFile, password)

	if err != nil {
		rc = 3
		rm = fmt.Sprintf("Unknown - %s", err)

		exitWithMsg(rc, rm)
	}

	var cert tls.Certificate
	for _, block := range pemBlocks {
		if block.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, block.Bytes)
		}
	}

	if len(cert.Certificate) == 0 {
		rc = 3
		rm = fmt.Sprintf("Unknown - no certificate found in \"%s\"", inFile)

		exitWithMsg(rc, rm)
	}

	return &cert
}

func getCertFromPem(rawFile []byte) *tls.Certificate {

	var cert tls.Certificate
	for {
		block, rest := pem.Decode(rawFile)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, block.Bytes)
		}
		rawFile = rest
	}

	if len(cert.Certificate) == 0 {
		rc = 3
		rm = fmt.Sprintf("Unknown - no certificate found in \"%s\", or is not in PEM format", inFile)

		exitWithMsg(rc, rm)
	}

	return &cert
}

func getCertFromDer(rawFile []byte) *x509.Certificate {
	certs, err := x509.ParseCertificates(rawFile)

	if err != nil {
		rc = 3
		rm = fmt.Sprintf("Unknown - %s, or is not in DER format", err)

		exitWithMsg(rc, rm)
	}

	return certs[0]
}

func getX509Cert(tlsCert *tls.Certificate) *x509.Certificate {
	x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		rc = 3
		rm = fmt.Sprintf("Unknown - %s", err)

		exitWithMsg(rc, rm)
	}
	return x509Cert
}

func main() {
	pkcs12Cmd := flag.NewFlagSet("pkcs12", flag.ExitOnError)
	pkcs12In := pkcs12Cmd.String("in", "", "The PKCS12 bundle")
	pkcs12Warn := pkcs12Cmd.Int("warn", 30, "The warning days")
	pkcs12Crit := pkcs12Cmd.Int("crit", 15, "The critical days")
	pkcs12Pass := pkcs12Cmd.String("pass", "", "The password")
	pkcs12NoPass := pkcs12Cmd.Bool("nopass", false, "Indicates the file is not protected by password")
	pkcs12File := false

	x509Cmd := flag.NewFlagSet("x509", flag.ExitOnError)
	x509In := x509Cmd.String("in", "", "The x509 cert")
	x509InForm := x509Cmd.String("inform", "pem", "The format of the input file")
	x509Warn := x509Cmd.Int("warn", 30, "The warning days")
	x509Crit := x509Cmd.Int("crit", 15, "The critical days")
	x509File := false

	if len(os.Args) < 3 {
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
			os.Exit(1)
		}
		inFile = *x509In

		if *x509InForm != "pem" && *x509InForm != "der" {
			fmt.Println("expected inform to be pem or der")
			os.Exit(1)
		}
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
	var x509Cert *x509.Certificate

	if pkcs12File {
		tlsCert = getCertFromP12(rawFile, *pkcs12Pass)
		x509Cert = getX509Cert(tlsCert)
	} else if x509File {
		if *x509InForm == "pem" {
			tlsCert = getCertFromPem(rawFile)
			x509Cert = getX509Cert(tlsCert)
		} else if *x509InForm == "der" {
			x509Cert = getCertFromDer(rawFile)
		}

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

	exitWithMsg(rc, rm)
}
