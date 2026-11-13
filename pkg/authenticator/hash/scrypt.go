package hash

import (
	"crypto/fips140"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

// Version is the hashing format version
const Version = 1

// MinFIPSSaltLen is the shortest salt that crypto/pbkdf2 accepts under GODEBUG=fips140=only
const MinFIPSSaltLen = 16

const hashFormat = "$%d:%x:%d:%d:%d:%s"

// minFIPSSecretLen is the shortest HMAC key, 112 bits, that Go accepts in fips140=only mode.
const minFIPSSecretLen = 14

var errSecretTooShort = fmt.Errorf("secret is shorter than %d bytes, which fips140=only mode requires", minFIPSSecretLen)

func checkSecretLen(secretKey string) error {
	if fips140.Enforced() && len(secretKey) < minFIPSSecretLen {
		return errSecretTooShort
	}
	return nil
}

// SCrypt contains all of the variables needed for scrypt hashing
type SCrypt struct {
	N       int
	R       int
	P       int
	KeyLen  int
	SaltLen int
}

// NewSCrypt returns a scrypt hasher with recommended default values
func NewSCrypt() Hasher {
	return SCrypt{
		N:       15,
		R:       8,
		P:       1,
		KeyLen:  64,
		SaltLen: 16,
	}
}

// CreateHash will return a hashed version of the secretKey, or an error
func (s SCrypt) CreateHash(secretKey string) (string, error) {
	if err := checkSecretLen(secretKey); err != nil {
		return "", err
	}

	salt := make([]byte, s.SaltLen)

	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	dk, err := scrypt.Key([]byte(secretKey), salt, 1<<s.N, s.R, s.P, s.KeyLen)
	if err != nil {
		return "", err
	}

	enc := base64.RawStdEncoding.EncodeToString(dk)
	hash := fmt.Sprintf(hashFormat, Version, salt, s.N, s.R, s.P, enc)

	return hash, nil
}

// VerifyHash will compare a secretKey and a hash, and return nil if they match
func (s SCrypt) VerifyHash(hash, secretKey string) error {
	if err := checkSecretLen(secretKey); err != nil {
		return err
	}

	var (
		version, n uint
		r, p       int
		enc        string
		salt       []byte
	)
	_, err := fmt.Sscanf(hash, hashFormat, &version, &salt, &n, &r, &p, &enc)
	if err != nil {
		return err
	}
	if version != Version {
		return fmt.Errorf("hash version %d does not match package version %d", version, Version)
	}

	if fips140.Enforced() && len(salt) < MinFIPSSaltLen {
		return fmt.Errorf("hash salt is %d bytes, fips140=only requires at least %d; delete the node password secret so the node can re-register", len(salt), MinFIPSSaltLen)
	}

	dk, err := base64.RawStdEncoding.DecodeString(enc)
	if err != nil {
		return err
	}

	verify, err := scrypt.Key([]byte(secretKey), salt, 1<<n, r, p, len(dk))
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(dk, verify) != 1 {
		return errors.New("hash does not match")
	}

	return nil
}
