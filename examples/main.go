package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"os"
	"time"

	"github.com/lkyzhu/xwt"
	"github.com/lkyzhu/xwt/examples/custom"
	"github.com/lkyzhu/xwt/jwt"
	"github.com/lkyzhu/xwt/method"
	"github.com/spf13/cobra"
)

func main() {

	cmd := cobra.Command{
		Use: "xwt",
	}

	encCmd := cobra.Command{
		Use: "enc",
		Run: encRun,
	}
	encCmd.Flags().String("type", "t", "type for xwt")
	encCmd.Flags().String("cert", "c", "cert for xwt")
	encCmd.Flags().String("alg", "c", "alg for xwt")
	cmd.AddCommand(&encCmd)

	decCmd := cobra.Command{
		Use: "dec",
		Run: decRun,
	}
	decCmd.Flags().String("type", "t", "type for xwt")
	decCmd.Flags().String("cert", "c", "cert for xwt")
	decCmd.Flags().String("alg", "c", "alg for xwt")
	decCmd.Flags().String("xwt", "x", "data for xwt")
	cmd.AddCommand(&decCmd)

	cmd.Execute()
}

func encRun(cmd *cobra.Command, args []string) {
	cert, _ := cmd.Flags().GetString("cert")
	data, err := os.ReadFile(cert)
	if err != nil {
		log.Fatalf("read cert fail, err:%s\n", err.Error())
	}

	key, err := loadPrivateKey(data)
	if err != nil {
		log.Fatalf("load private key fail, err:%v\n", err.Error())
	}

	var sMethod method.SigningMethod
	alg, _ := cmd.Flags().GetString("alg")
	switch alg {
	case "es":
		sMethod = method.SigningMethodES256
	case "hmac":
		key = data
		sMethod = method.SigningMethodHS256
	}

	var claims xwt.Claims
	sType, _ := cmd.Flags().GetString("type")
	switch sType {
	case "jwt":
		claims = &custom.JwtCustomClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "lkyzhu",
				Subject:   sType,
				Audience:  []string{"a1", "a2"},
				ExpiresAt: time.Now().AddDate(1, 0, 0).Unix(),
				IssuedAt:  time.Now().Unix(),
				NotBefore: time.Now().Unix(),
			},
			Name: "Custom-JWT",
			Age:  21,
		}
	default:
		claims = &custom.CustomClaims{
			Claims: &custom.StandardClaims{
				Issuer:    "lkyzhu",
				Subject:   "pwt",
				Audience:  []string{"a1", "a2"},
				ExpiresAt: time.Now().AddDate(1, 0, 0).Unix(),
				IssuedAt:  time.Now().Unix(),
				NotBefore: time.Now().Unix(),
			},
			Name: "Custom-PWT",
			Age:  21,
		}
	}

	token := xwt.NewWithClaims(sMethod, claims)
	str, err := token.SignedString(key)
	if err != nil {
		log.Fatalf("sign claims fail, err:%v\n", err.Error())
	}
	log.Printf("sign claims success, ret:%s\n", str)

}

func decRun(cmd *cobra.Command, args []string) {
	path, _ := cmd.Flags().GetString("cert")
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read cert fail, err:%s\n", err.Error())
	}

	cert, err := loadCert(data)
	if err != nil {
		log.Fatalf("load private key fail, err:%v\n", err.Error())
	}

	key := cert.PublicKey

	var sMethod method.SigningMethod
	alg, _ := cmd.Flags().GetString("alg")
	switch alg {
	case "es":
		sMethod = method.SigningMethodES256
	case "hmac":
		key = data
		sMethod = method.SigningMethodHS256
	}
	log.Printf("method:%v\n", sMethod)

	var claims xwt.Claims
	sType, _ := cmd.Flags().GetString("type")
	switch sType {
	case "jwt":
		claims = &custom.JwtCustomClaims{}
	default:
		claims = &custom.CustomClaims{}
	}

	xData, _ := cmd.Flags().GetString("xwt")
	token, err := xwt.ParseWithClaims(xData, claims, func(t *xwt.Token) (interface{}, error) { return key, nil })
	if err != nil {
		log.Fatalf("parse token claims fail, err:%v\n", err.Error())
	}

	log.Printf("parse token claims[%v] success\n", token.Claims)
}

func loadPrivateKey(data []byte) (crypto.PrivateKey, error) {
	var keyBlock *pem.Block
	for len(data) > 0 {
		keyBlock, data = pem.Decode(data)
		switch keyBlock.Type {
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(keyBlock.Bytes)
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		case "PRIVATE KEY", "ED25519 Private-Key":
			return x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		}

	}

	return nil, errors.New("not support")
}

func loadCert(data []byte) (*x509.Certificate, error) {
	var keyBlock *pem.Block
	for len(data) > 0 {
		keyBlock, data = pem.Decode(data)
		switch keyBlock.Type {
		case "CERTIFICATE":
			if c, err := x509.ParseCertificate(keyBlock.Bytes); err == nil {
				return c, nil
			}
		}
	}

	return nil, errors.New("not support")
}
