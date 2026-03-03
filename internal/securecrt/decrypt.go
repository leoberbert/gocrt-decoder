package securecrt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const v2Prefix = "02:"

// DecryptPasswordV2 decrypts SecureCRT Password V2 values.
// It accepts both "02:<hex>" and "<hex>" formats.
func DecryptPasswordV2(value, configPassphrase string) (string, error) {
	cipherHex := strings.TrimSpace(value)
	if cipherHex == "" {
		return "", nil
	}

	if strings.HasPrefix(cipherHex, v2Prefix) {
		cipherHex = strings.TrimPrefix(cipherHex, v2Prefix)
	}

	cipheredBytes, err := hex.DecodeString(cipherHex)
	if err != nil {
		return "", fmt.Errorf("invalid encrypted password format: %w", err)
	}
	if len(cipheredBytes) == 0 {
		return "", nil
	}

	key := sha256.Sum256([]byte(configPassphrase))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", fmt.Errorf("failed to initialize AES cipher: %w", err)
	}
	blockSize := block.BlockSize()
	if len(cipheredBytes)%blockSize != 0 {
		return "", errors.New("invalid encrypted password length")
	}

	iv := make([]byte, blockSize)
	plain := make([]byte, len(cipheredBytes))
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(plain, cipheredBytes)

	if len(plain) < 4 {
		return "", errors.New("invalid encrypted password payload")
	}

	plainLen := int(binary.LittleEndian.Uint32(plain[:4]))
	payloadLen := 4 + plainLen + sha256.Size
	if plainLen < 0 || payloadLen > len(plain) {
		return "", errors.New("invalid encrypted password payload")
	}

	plainBytes := plain[4 : 4+plainLen]
	digest := plain[4+plainLen : payloadLen]
	expected := sha256.Sum256(plainBytes)
	if !equalBytes(digest, expected[:]) {
		return "", errors.New("encrypted password integrity check failed")
	}

	return string(plainBytes), nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
