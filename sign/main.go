package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/tendermint/go-crypto"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("usage: %s <hex-enoded private key> <hex-encoded message>\n", os.Args[0])
	}

	privKeyHex := os.Args[1]
	messageDataHex := os.Args[2]

	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		log.Fatal("error: cannot decode private key: ", err.Error())
	}
	messageData, err := hex.DecodeString(messageDataHex)
	if err != nil {
		log.Fatal("error: cannot decode message: ", err.Error())
	}
	privKey, err := crypto.PrivKeyFromBytes(privKeyBytes)
	if err != nil {
		log.Fatal("error: cannot read private key: ", err.Error())
	}
	signature := privKey.Sign(messageData).Bytes()
	fmt.Printf("%X\n", signature)

}
