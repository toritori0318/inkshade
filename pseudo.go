package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const MaskStylePseudo MaskStyle = "pseudo"

func pseudonymize(ruleID, original string) string {
	h := sha256.Sum256([]byte(original))
	hash := hex.EncodeToString(h[:])[:8]

	switch ruleID {
	case "email":
		return fmt.Sprintf("user_%s@masked.example", hash)
	case "credit_card":
		return fmt.Sprintf("****-****-%s-%s", hash[:4], hash[4:8])
	case "phone":
		return fmt.Sprintf("***-%s-%s", hash[:4], hash[4:8])
	default:
		return fmt.Sprintf("[PSEUDO_%s]", hash)
	}
}
