package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/icon-project/goloop/common/crypto"
)

func TestRecoverPublicKeyFromSignature(t *testing.T) {
	txHash := "0x70f4a698e3f6841a24baf5f1cbcd3ea07782752b5014b3a0e7754ef10fb20763"
	signature := "3/nMLS9qFCnYjxBmlAp+o3DMRmKLSsxaLPLbPumB+CNSSA93B8rR1iVWeXoETJS3FnUjbFMYlXSWXo+kCCtTpAE="
	expectedPubKeyString := "0x02fa6bff597a4e94be45071e7e2b4bdef183de9f9bf86c863906932ab81ecfd17a"

	if strings.HasPrefix(expectedPubKeyString, "0x") {
		expectedPubKeyString = expectedPubKeyString[2:]
	}

	expectedPubKeyBytes, err := hex.DecodeString(expectedPubKeyString)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
		return
	}

	expectedPubKey, err := crypto.ParsePublicKey(expectedPubKeyBytes)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
		return
	}

	pubKey, err := recoverPublicKeyFromSignature(txHash, signature)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
		return
	}

	if pubKey != expectedPubKey {
		t.Errorf("Expected %s, but got %s", expectedPubKey, pubKey)
	}
}
