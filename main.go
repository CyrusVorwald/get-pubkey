package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/icon-project/goloop/common/crypto"
)

func recoverPublicKeyFromSignature(txHashHex string, signatureBase64 string) (*crypto.PublicKey, error) {
	// Decode transaction hash
	if strings.HasPrefix(txHashHex, "0x") {
		txHashHex = txHashHex[2:]
	}

	txHashBytes, err := hex.DecodeString(txHashHex)
	if err != nil {
		return nil, err
	}

	// Decode Base64 signature to bytes
	sigBytes, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return nil, err
	}

	// Parse the signature
	sig, err := crypto.ParseSignature(sigBytes)
	if err != nil {
		return nil, err
	}

	// Recover the public key
	return sig.RecoverPublicKey(txHashBytes)
}

func main() {
	txHash := "0x516d2ecad0b5e37899900ddd6d2bfd94d7a2680b1401876214b873ce3d5c9846"
	signature := "AXrPcOq5HgkKwaf0vCJ+WmKSgIDv/dpZLBkqh1G8oBVowdRLaEFNfRmj5LlQ3Lggpcdpc/cs1ZZKVZcNsIhNwQA="

	pubKey, err := recoverPublicKeyFromSignature(txHash, signature)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Output the recovered public key
	fmt.Println("Recovered Public Key:", pubKey.String())
}
