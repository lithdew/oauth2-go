package oauth2

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"
)

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
