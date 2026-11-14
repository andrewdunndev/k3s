package handlers

import (
	"context"
	"crypto/fips140"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/k3s-io/k3s/pkg/authenticator/hash"
	"github.com/k3s-io/k3s/pkg/daemons/config"
	"github.com/k3s-io/k3s/pkg/passwd"
)

func Test_UnitTokenRotateShortToken(t *testing.T) {
	if !fips140.Enforced() {
		t.Skip("short tokens are accepted outside fips140=only mode")
	}

	oldToken := strings.Repeat("A", 20)
	passwdFile := filepath.Join(t.TempDir(), "passwd")
	p, err := passwd.Read(passwdFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.EnsureUser("server", "k3s:server", oldToken); err != nil {
		t.Fatal(err)
	}
	if err := p.Write(passwdFile); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(passwdFile)
	if err != nil {
		t.Fatal(err)
	}

	control := &config.Control{Runtime: &config.ControlRuntime{}}
	control.Runtime.PasswdFile = passwdFile
	err = tokenRotate(context.Background(), control, strings.Repeat("B", 8))
	if !errors.Is(err, hash.ErrSecretTooShort) {
		t.Errorf("tokenRotate() error = %v, want %v", err, hash.ErrSecretTooShort)
	}

	after, err := os.ReadFile(passwdFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Errorf("password file changed by a refused rotation")
	}
}
