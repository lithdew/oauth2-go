package oauth2

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"regexp"
	"strings"
)

var CodeVerifierRegex = regexp.MustCompile(`[-._~a-zA-Z0-9]{43,128}`)

func GenerateOpaqueValue(secret []byte) (string, string, string, error) {
	var val [32]byte
	if _, err := io.ReadFull(rand.Reader, val[:]); err != nil {
		return "", "", "", err
	}

	var mac [sha256.Size]byte
	hasher := hmac.New(sha256.New, secret)
	hasher.Write(val[:])
	hasher.Sum(mac[:0])

	encodedValue := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(val[:])
	encodedMAC := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(mac[:])

	var b strings.Builder
	b.WriteString(encodedValue)
	b.WriteByte('.')
	b.WriteString(encodedMAC)

	return b.String(), encodedValue, encodedMAC, nil
}

func VerifyOpaqueValue(secret []byte, opaque string) error {
	fields := strings.Split(opaque, ".")
	if len(fields) != 2 {
		return errors.New("malformed opaque value")
	}

	val, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(fields[0])
	if err != nil {
		return err
	}

	actual, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(fields[1])
	if err != nil {
		return err
	}

	var expected [sha256.Size]byte
	hasher := hmac.New(sha256.New, secret)
	hasher.Write(val[:])
	hasher.Sum(expected[:0])

	if !hmac.Equal(expected[:], actual) {
		return errors.New("failed to verify opaque value")
	}

	return nil
}

func GenerateCodeVerifierPKCE() (string, error) {
	const set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	const bitsPerIndex = 7
	const bitsPerIndexMask = 1<<bitsPerIndex - 1

	var result [128]byte

	for i, j, buf := 0, 0, []byte{}; i < 128; j++ {
		if j%166 == 0 {
			buf = make([]byte, 166)
			if _, err := io.ReadFull(rand.Reader, buf); err != nil {
				return "", err
			}
		}
		if index := int(buf[j&127] & bitsPerIndexMask); index < len(set) {
			result[i] = set[index]
			i++
		}
	}

	return string(result[:]), nil
}

func GenerateCodeChallengePKCE(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
}
