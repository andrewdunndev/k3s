package main

import (
	"flag"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/k3s-io/k3s/tests"
	"github.com/k3s-io/k3s/tests/docker"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var tc *docker.TestConfig
var ci = flag.Bool("ci", false, "running on CI")
var fipsMode = flag.String("fipsMode", "only", "GODEBUG fips140 value to run the cluster under")

func Test_DockerFIPS(t *testing.T) {
	flag.Parse()
	RegisterFailHandler(Fail)
	RunSpecs(t, "FIPS Docker Test Suite")
}

// setGODEBUG writes the mode into the environment file that install.sh creates for the unit
func setGODEBUG(node docker.DockerNode, unit, mode string) {
	cmd := fmt.Sprintf("sed -i '/^GODEBUG=/d' /etc/systemd/system/%s.service.env; echo 'GODEBUG=fips140=%s' >> /etc/systemd/system/%s.service.env", unit, mode, unit)
	Expect(node.RunCmdOnNode(cmd)).Error().NotTo(HaveOccurred())
}

// processGODEBUG reads GODEBUG from the environment of the running k3s process
func processGODEBUG(node docker.DockerNode) (string, error) {
	return node.RunCmdOnNode(`tr '\\0' '\\n' < /proc/\$(pgrep -o -x k3s)/environ | grep ^GODEBUG=`)
}

var _ = Describe("FIPS Tests", Ordered, func() {

	Context("Setup Cluster", func() {
		It("should provision a server under GODEBUG=fips140", func() {
			var err error
			tc, err = docker.NewTestConfig(GinkgoTB(), "ghcr.io/rancher/systemd-node:v0.0.9")
			Expect(err).NotTo(HaveOccurred())
			// fips140=only rejects HMAC keys shorter than 112 bits, and the default test token is 12 characters
			tc.Token = fmt.Sprintf("%020d", rand.Int63n(1000000000000))
			tc.SkipStart = true
			Expect(tc.ProvisionServers(1)).To(Succeed())
			for _, server := range tc.Servers {
				setGODEBUG(server, "k3s", *fipsMode)
				Expect(server.RunCmdOnNode("systemctl start k3s")).Error().NotTo(HaveOccurred())
			}
			Expect(tc.CopyAndModifyKubeconfig()).To(Succeed())
			Eventually(func() error {
				return tests.CheckDefaultDeployments(tc.KubeconfigFile)
			}, "120s", "5s").Should(Succeed())
			Eventually(func() error {
				return tests.NodesReady(tc.KubeconfigFile, tc.GetServerNames())
			}, "60s", "5s").Should(Succeed())
		})
		It("runs the server in the requested mode", func() {
			for _, server := range tc.Servers {
				Expect(processGODEBUG(server)).To(ContainSubstring("fips140=" + *fipsMode))
			}
		})
		It("passes the runc self-check", func() {
			for _, server := range tc.Servers {
				cmd := fmt.Sprintf("GODEBUG=fips140=%s /var/lib/rancher/k3s/data/current/bin/runc --version", *fipsMode)
				Expect(server.RunCmdOnNode(cmd)).To(ContainSubstring("runc version"))
			}
		})
	})

	Context("Verify workloads", func() {
		It("runs a pod", func() {
			res, err := tc.DeployWorkload("clusterip.yaml")
			Expect(err).NotTo(HaveOccurred(), "Cluster IP manifest not deployed: "+res)
			Eventually(func(g Gomega) {
				cmd := "kubectl get pods -o=name -l k8s-app=nginx-app-clusterip --field-selector=status.phase=Running --kubeconfig=" + tc.KubeconfigFile
				res, err := tests.RunCommand(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(res).Should(ContainSubstring("test-clusterip"), "failed cmd: %q result: %s", cmd, res)
			}, "240s", "5s").Should(Succeed())
		})
		It("execs into the pod", func() {
			Eventually(func() (string, error) {
				return tests.RunCommand("kubectl exec deploy/test-clusterip --kubeconfig=" + tc.KubeconfigFile + " -- echo fips-exec-ok")
			}, "60s", "5s").Should(ContainSubstring("fips-exec-ok"))
		})
		It("applies a network policy", func() {
			res, err := tc.DeployWorkload("fips-netpol.yaml")
			Expect(err).NotTo(HaveOccurred(), "Network policy not deployed: "+res)
			Eventually(func(g Gomega) {
				out, err := tc.Servers[0].RunCmdOnNode("iptables-save | grep -c KUBE-NWPLCY || true")
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(strings.TrimSpace(out)).NotTo(Equal("0"))
			}, "60s", "5s").Should(Succeed())
			Consistently(func() error {
				return tests.NodesReady(tc.KubeconfigFile, tc.GetServerNames())
			}, "20s", "5s").Should(Succeed())
		})
	})

	Context("Verify agent join", func() {
		It("joins an agent under the same mode", func() {
			Expect(tc.ProvisionAgents(1)).To(Succeed())
			for _, agent := range tc.Agents {
				setGODEBUG(agent, "k3s-agent", *fipsMode)
				Expect(agent.RunCmdOnNode("systemctl start k3s-agent")).Error().NotTo(HaveOccurred())
			}
			Eventually(func() error {
				return tests.NodesReady(tc.KubeconfigFile, tc.GetNodeNames())
			}, "120s", "5s").Should(Succeed())
			for _, agent := range tc.Agents {
				Expect(processGODEBUG(agent)).To(ContainSubstring("fips140=" + *fipsMode))
			}
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
