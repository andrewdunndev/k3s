package main

import (
	"flag"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/k3s-io/k3s/pkg/authenticator/hash"
	"github.com/k3s-io/k3s/tests"
	"github.com/k3s-io/k3s/tests/docker"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var tc *docker.TestConfig
var ci = flag.Bool("ci", false, "running on CI")

func Test_DockerFIPSMigration(t *testing.T) {
	flag.Parse()
	RegisterFailHandler(Fail)
	RunSpecs(t, "FIPS Migration Docker Test Suite")
}

// setMode writes the mode into the server's environment file, and restarts every node.
// An empty mode leaves GODEBUG unset.
func setMode(mode string) {
	for _, server := range tc.Servers {
		cmd := "sed -i '/^GODEBUG=/d' /etc/systemd/system/k3s.service.env"
		if mode != "" {
			cmd += "; echo 'GODEBUG=fips140=" + mode + "' >> /etc/systemd/system/k3s.service.env"
		}
		Expect(server.RunCmdOnNode(cmd)).Error().NotTo(HaveOccurred())
	}
	Expect(docker.RestartCluster(append(tc.Servers, tc.Agents...))).To(Succeed())
}

// processGODEBUG reads GODEBUG from the environment of the running k3s process
func processGODEBUG(node docker.DockerNode, unit string) (string, error) {
	return node.RunCmdOnNode(`tr '\\0' '\\n' < /proc/\$(systemctl show -p MainPID --value ` + unit + `)/environ | grep ^GODEBUG=`)
}

// legacyHash returns a node password hash as created before the salt was lengthened
func legacyHash(password string) string {
	hasher := hash.NewSCrypt().(hash.SCrypt)
	hasher.SaltLen = 8
	legacy, err := hasher.CreateHash(password)
	Expect(err).NotTo(HaveOccurred())
	return legacy
}

var _ = Describe("FIPS Migration Tests", Ordered, func() {
	var secret, password string

	Context("Setup Cluster", func() {
		It("should provision a server and an agent with fips140 unset", func() {
			var err error
			tc, err = docker.NewTestConfig(GinkgoTB(), "ghcr.io/rancher/systemd-node:v0.0.9")
			Expect(err).NotTo(HaveOccurred())
			// fips140=only rejects HMAC keys shorter than 112 bits, and the default test token is 12 characters
			tc.Token = fmt.Sprintf("%020d", rand.Int63n(1000000000000))
			Expect(tc.ProvisionServers(1)).To(Succeed())
			Expect(tc.CopyAndModifyKubeconfig()).To(Succeed())
			Expect(tc.ProvisionAgents(1)).To(Succeed())
			Eventually(func() error {
				return tests.CheckDefaultDeployments(tc.KubeconfigFile)
			}, "120s", "5s").Should(Succeed())
			Eventually(func() error {
				return tests.NodesReady(tc.KubeconfigFile, tc.GetNodeNames())
			}, "60s", "5s").Should(Succeed())
		})
		It("replaces the agent's node password secret with a legacy 8-byte salt hash", func() {
			secret = strings.ToLower(tc.Agents[0].Name) + ".node-password.k3s"
			out, err := tc.Agents[0].RunCmdOnNode("cat /etc/rancher/node/password")
			Expect(err).NotTo(HaveOccurred())
			password = strings.TrimSpace(out)
			// the secret is immutable, so it is deleted and created again
			cmd := fmt.Sprintf("kubectl delete secret -n kube-system %s --kubeconfig=%s", secret, tc.KubeconfigFile)
			Expect(tests.RunCommand(cmd)).Error().NotTo(HaveOccurred())
			cmd = fmt.Sprintf("kubectl create secret generic -n kube-system %s --type=k3s.cattle.io/node-password --from-literal=hash='%s' --kubeconfig=%s",
				secret, legacyHash(password), tc.KubeconfigFile)
			Expect(tests.RunCommand(cmd)).Error().NotTo(HaveOccurred())
		})
	})

	Context("Enable fips140=on", func() {
		It("restarts and the legacy node password still verifies", func() {
			setMode("on")
			Eventually(func() error {
				return tests.CheckDefaultDeployments(tc.KubeconfigFile)
			}, "180s", "5s").Should(Succeed())
			Eventually(func() error {
				return tests.NodesReady(tc.KubeconfigFile, tc.GetNodeNames())
			}, "120s", "5s").Should(Succeed())
		})
	})

	Context("Enable fips140=only", func() {
		It("restarts the server and it becomes ready", func() {
			setMode("only")
			Eventually(func() error {
				return tests.CheckDefaultDeployments(tc.KubeconfigFile)
			}, "180s", "5s").Should(Succeed())
			Eventually(func() error {
				return tests.NodesReady(tc.KubeconfigFile, tc.GetServerNames())
			}, "120s", "5s").Should(Succeed())
		})
		It("runs the server in the requested mode", func() {
			for _, server := range tc.Servers {
				Expect(processGODEBUG(server, "k3s")).To(ContainSubstring("fips140=only"))
			}
		})
		It("rejects the agent with the legacy node password", func() {
			Eventually(func() (string, error) {
				return tc.Agents[0].RunCmdOnNode("journalctl -u k3s-agent --no-pager | grep -c 'Node password rejected' || true")
			}, "120s", "5s").ShouldNot(Equal("0\n"))
			Eventually(func() error {
				return tests.NodesReady(tc.KubeconfigFile, tc.GetAgentNames())
			}, "180s", "5s").ShouldNot(Succeed())
		})
	})

	Context("Rejoin the agent", func() {
		It("joins again once its node password secret is deleted", func() {
			cmd := fmt.Sprintf("kubectl delete secret -n kube-system %s --kubeconfig=%s", secret, tc.KubeconfigFile)
			Expect(tests.RunCommand(cmd)).Error().NotTo(HaveOccurred())
			Expect(tc.Agents[0].RunCmdOnNode("systemctl restart k3s-agent")).Error().NotTo(HaveOccurred())
			Eventually(func() error {
				return tests.NodesReady(tc.KubeconfigFile, tc.GetNodeNames())
			}, "180s", "5s").Should(Succeed())
		})
		It("stays joined after returning to fips140=on", func() {
			setMode("on")
			Eventually(func() error {
				return tests.NodesReady(tc.KubeconfigFile, tc.GetNodeNames())
			}, "180s", "5s").Should(Succeed())
		})
	})
})

var failed bool
var _ = AfterEach(func() {
	failed = failed || CurrentSpecReport().Failed()
})

var _ = AfterSuite(func() {
	if failed {
		AddReportEntry("journald-logs", docker.TailJournalLogs(1000, append(tc.Servers, tc.Agents...)))
	}
	if *ci || (tc != nil && !failed) {
		Expect(tc.Cleanup()).To(Succeed())
	}
})
