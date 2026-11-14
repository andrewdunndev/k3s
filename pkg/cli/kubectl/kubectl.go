package kubectl

import (
	"crypto/fips140"

	"github.com/k3s-io/k3s/pkg/kubectl"
	"github.com/urfave/cli/v2"
)

func Run(ctx *cli.Context) error {
	// client-go's websocket exec fallback computes the RFC 6455 accept key with SHA-1
	fips140.WithoutEnforcement(kubectl.Main)
	return nil
}
