package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"io"
	"log"
	"math/big"
	"os"
)

var (
	gen    = flag.Bool("keygen", false, "Generate keypair.")
	key    = flag.String("key", "", "Private/Public key.")
	sig    = flag.String("signature", "", "Signature.")
	sign   = flag.Bool("sign", false, "Sign with Private key.")
	verify = flag.Bool("verify", false, "Verify with Public key.")
)

func main() {
	flag.Parse()

	var privatekey *ecdsa.PrivateKey
	var pubkey ecdsa.PublicKey
	var pub *ecdsa.PublicKey
	var err error
	var pubkeyCurve elliptic.Curve

	pubkeyCurve = elliptic.P256()
	
	if *gen {
		if *key != "" {
			privatekey, err = ReadPrivateKeyFromHex(*key)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			privatekey = new(ecdsa.PrivateKey)
			privatekey, err = ecdsa.GenerateKey(pubkeyCurve, rand.Reader)

			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}
		pubkey = privatekey.PublicKey
		fmt.Println("Private= " + WritePrivateKeyToHex(privatekey))
		fmt.Println("Public= " + WritePublicKeyToHex(&pubkey))
		os.Exit(0)
	}

	if *sign {
		var h hash.Hash
		h = sha256.New()

		if _, err := io.Copy(h, os.Stdin); err != nil {
			panic(err)
		}

		privatekey, err = ReadPrivateKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}

		signature, err := Sign(h.Sum(nil), privatekey)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%x\n", signature)
	}

	if *verify {
		var h hash.Hash
		h = sha256.New()

		if _, err := io.Copy(h, os.Stdin); err != nil {
			panic(err)
		}

		pub, err = ReadPublicKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}

		sig, _ := hex.DecodeString(*sig)

		verifystatus := Verify(h.Sum(nil), sig, pub)
		fmt.Println(verifystatus)
	}
}

func Verify(data, signature []byte, pubkey *ecdsa.PublicKey) bool {
	digest := sha256.Sum256(data)

	curveOrderByteSize := pubkey.Curve.Params().P.BitLen() / 8

	r, s := new(big.Int), new(big.Int)
	r.SetBytes(signature[:curveOrderByteSize])
	s.SetBytes(signature[curveOrderByteSize:])

	return ecdsa.Verify(pubkey, digest[:], r, s)
}

func Sign(data []byte, privkey *ecdsa.PrivateKey) ([]byte, error) {
	digest := sha256.Sum256(data)

	r, s, err := ecdsa.Sign(rand.Reader, privkey, digest[:])
	if err != nil {
		return nil, err
	}

	params := privkey.Curve.Params()
	curveOrderByteSize := params.P.BitLen() / 8
	rBytes, sBytes := r.Bytes(), s.Bytes()
	signature := make([]byte, curveOrderByteSize*2)
	copy(signature[curveOrderByteSize-len(rBytes):], rBytes)
	copy(signature[curveOrderByteSize*2-len(sBytes):], sBytes)

	return signature, nil
}
