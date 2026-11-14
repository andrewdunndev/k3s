package hash

import (
	"crypto/fips140"
	"errors"
	"strings"
	"testing"
)

func Test_UnitSCrypt_VerifyHash(t *testing.T) {
	type args struct {
		secretKey string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Basic Hash Test",
			args: args{
				secretKey: "hello world, hello",
			},
		},
		{
			name: "Long Hash Test",
			args: args{
				secretKey: strings.Repeat("A", 720),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := NewSCrypt()
			hash, _ := hasher.CreateHash(tt.args.secretKey)
			if err := hasher.VerifyHash(hash, tt.args.secretKey); (err != nil) != tt.wantErr {
				t.Errorf("SCrypt.VerifyHash() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_UnitSCrypt_CreateHash_SaltLength(t *testing.T) {
	hash, err := NewSCrypt().CreateHash("hello world, long enough")
	if err != nil {
		t.Fatal(err)
	}
	if salt := strings.Split(hash, ":")[1]; len(salt) != 32 {
		t.Errorf("salt is %d hex characters, want 32", len(salt))
	}
}

// legacyHash is "hello world" hashed by the 8-byte-salt SCrypt that predates the 16-byte salt.
const legacyHash = "$1:c229c44d4c4adb07:15:8:1:8TozcojzhYRmvoYMOzClhBJ5EomfBg+6yClpqo15t0j2ENlD+cVwcVdIyqo02V6JK05zToAusxPYmytPIus/kQ"

func Test_UnitSCrypt_VerifyHash_LegacySalt(t *testing.T) {
	if fips140.Enforced() {
		t.Skip("fips140=only rejects the 8-byte salt, see Test_UnitSCrypt_VerifyHash_LegacySaltFIPS")
	}
	hasher := NewSCrypt()
	if err := hasher.VerifyHash(legacyHash, "hello world"); err != nil {
		t.Fatalf("SCrypt.VerifyHash() error = %v, want nil for a stock 8-byte-salt hash", err)
	}
	if err := hasher.VerifyHash(legacyHash, "wrong"); err == nil {
		t.Fatal("SCrypt.VerifyHash() accepted the wrong secret")
	}
}

func Test_UnitSCrypt_VerifyHash_LegacySaltFIPS(t *testing.T) {
	if !fips140.Enforced() {
		t.Skip("requires GODEBUG=fips140=only")
	}
	err := NewSCrypt().VerifyHash(legacyHash, "hello world, long enough")
	if err == nil {
		t.Fatal("SCrypt.VerifyHash() error = nil, want an error for an 8-byte salt under fips140=only")
	}
	if !strings.Contains(err.Error(), "delete the node password secret") {
		t.Errorf("SCrypt.VerifyHash() error = %q, want it to name the remedy", err)
	}
}

func Test_UnitSCrypt_ShortSecret(t *testing.T) {
	if !fips140.Enforced() {
		t.Skip("short secrets are accepted outside fips140=only mode")
	}
	hasher := NewSCrypt()
	valid, err := hasher.CreateHash(strings.Repeat("A", minFIPSSecretLen))
	if err != nil {
		t.Fatal(err)
	}
	secret := strings.Repeat("A", minFIPSSecretLen-1)
	if _, err := hasher.CreateHash(secret); !errors.Is(err, ErrSecretTooShort) {
		t.Errorf("CreateHash() error = %v, want %v", err, ErrSecretTooShort)
	}
	if err := hasher.VerifyHash(valid, secret); !errors.Is(err, ErrSecretTooShort) {
		t.Errorf("VerifyHash() error = %v, want %v", err, ErrSecretTooShort)
	}
}

func Test_UnitSCrypt_ShortSecretOutsideOnly(t *testing.T) {
	if fips140.Enforced() {
		t.Skip("short secrets are rejected in fips140=only mode")
	}
	hasher := NewSCrypt()
	hash, err := hasher.CreateHash("abc")
	if err != nil {
		t.Fatal(err)
	}
	if err := hasher.VerifyHash(hash, "abc"); err != nil {
		t.Errorf("VerifyHash() error = %v", err)
	}
}

func FuzzVerifyHash(f *testing.F) {
	hasher := NewSCrypt()
	validSecret := "my-secret-password"
	validHash, _ := hasher.CreateHash(validSecret)

	// Seed the fuzzer with some valid and invalid inputs
	f.Add(validHash, validSecret)
	f.Add(validHash, "wrong-password")
	f.Add("", "")
	f.Add("$1:deadbeef:f:8:1:corrupt-hash", "any-password")
	f.Add("", validSecret)
	f.Add(validHash, "")

	f.Fuzz(func(t *testing.T, hash, secretKey string) {
		_ = hasher.VerifyHash(hash, secretKey)
	})
}
