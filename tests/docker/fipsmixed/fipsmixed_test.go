package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/k3s-io/k3s/tests"
	"github.com/k3s-io/k3s/tests/docker"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
)

var tc *docker.TestConfig
var ci = flag.Bool("ci", false, "running on CI")
var oldBinary = flag.String("oldBinary", "", "path to a k3s build without the bootstrap migration guard; the suite is skipped without it")

const (
	artifact = "../../../dist/artifacts/k3s"
	annotKey = `k3s\.io/bootstrap-sha256`
	migrated = "migrated bootstrap key"
)

func Test_DockerFIPSMixedVersion(t *testing.T) {
	flag.Parse()
	RegisterFailHandler(Fail)
	RunSpecs(t, "FIPS Mixed Version Docker Test Suite")
}

// installArtifact replaces the file that new containers bind-mount as /usr/local/bin/k3s.
// The rename gives the path a new inode, so a container created earlier keeps the binary it started with.
func installArtifact(src string) {
	tmp := artifact + ".swap"
	data, err := os.ReadFile(src)
	Expect(err).NotTo(HaveOccurred())
	Expect(os.WriteFile(tmp, data, 0755)).To(Succeed())
	Expect(os.Rename(tmp, artifact)).To(Succeed())
}

func setMode(mode string) {
	for _, server := range tc.Servers {
		cmd := "sed -i '/^GODEBUG=/d' /etc/systemd/system/k3s.service.env; echo 'GODEBUG=fips140=" + mode + "' >> /etc/systemd/system/k3s.service.env"
		Expect(server.RunCmdOnNode(cmd)).Error().NotTo(HaveOccurred())
	}
	Expect(docker.RestartCluster(tc.Servers)).To(Succeed())
}

func logCount(node docker.DockerNode, pattern string) int {
	out, err := node.RunCmdOnNode("journalctl -u k3s --no-pager | grep -c '" + pattern + "' || true")
	Expect(err).NotTo(HaveOccurred())
	n, err := strconv.Atoi(strings.TrimSpace(out))
	Expect(err).NotTo(HaveOccurred())
	return n
}

func nodeReady(name string) error {
	nodes, err := tests.ParseNodes(tc.KubeconfigFile)
	if err != nil {
		return err
	}
	for _, node := range nodes {
		if node.Name != name {
			continue
		}
		for _, condition := range node.Status.Conditions {
			if condition.Type == corev1.NodeReady && condition.Status == corev1.ConditionTrue {
				return nil
			}
		}
		return fmt.Errorf("node %s is not ready", name)
	}
	return fmt.Errorf("node %s not found", name)
}

func annotation(name string) string {
	cmd := fmt.Sprintf("kubectl get node %s -o jsonpath='{.metadata.annotations.%s}' --kubeconfig=%s", name, annotKey, tc.KubeconfigFile)
	out, err := tests.RunCommand(cmd)
	Expect(err).NotTo(HaveOccurred())
	return strings.TrimSpace(out)
}

var _ = Describe("FIPS Mixed Version Tests", Ordered, func() {
	var oldName, newName string

	BeforeAll(func() {
		if *oldBinary == "" {
			Skip("-oldBinary is not set")
		}
	})

	Context("Setup Cluster", func() {
		It("starts one server without the guard and joins one with it", func() {
			current, err := os.ReadFile(artifact)
			Expect(err).NotTo(HaveOccurred())
			currentPath := filepath.Join(GinkgoT().TempDir(), "k3s-current")
			Expect(os.WriteFile(currentPath, current, 0755)).To(Succeed())
			DeferCleanup(func() { installArtifact(currentPath) })

			tc, err = docker.NewTestConfig(GinkgoTB(), "ghcr.io/rancher/systemd-node:v0.0.9")
			Expect(err).NotTo(HaveOccurred())
			// fips140=only rejects HMAC keys shorter than 112 bits, and the default test token is 12 characters
			tc.Token = fmt.Sprintf("%020d", rand.Int63n(1000000000000))
			tc.DBType = "etcd"

			installArtifact(*oldBinary)
			Expect(tc.ProvisionServers(1)).To(Succeed())
			Expect(tc.CopyAndModifyKubeconfig()).To(Succeed())
			installArtifact(currentPath)
			Expect(tc.ProvisionServers(2)).To(Succeed())

			oldName, newName = tc.GetServerNames()[0], tc.GetServerNames()[1]
			Eventually(func() error {
				return tests.NodesReady(tc.KubeconfigFile, tc.GetNodeNames())
			}, "180s", "5s").Should(Succeed())
		})
	})

	Context("Enable fips140=on with the old server as a member", func() {
		It("restarts both servers", func() {
			setMode("on")
			Eventually(func() error {
				return tests.NodesReady(tc.KubeconfigFile, tc.GetNodeNames())
			}, "240s", "5s").Should(Succeed())
		})
		It("defers the rewrite and names the old server", func() {
			Eventually(func() int {
				return logCount(tc.Servers[1], "Deferring bootstrap data migration to SHA-256 until all control-plane nodes support it; waiting on nodes: "+oldName)
			}, "150s", "5s").Should(BeNumerically(">", 0))
			Expect(annotation(newName)).NotTo(BeEmpty())
			Expect(annotation(oldName)).To(BeEmpty())
		})
		It("leaves the data readable by the old server across the next retry", func() {
			// the retry runs once a minute
			Consistently(func() int {
				return logCount(tc.Servers[0], migrated) + logCount(tc.Servers[1], migrated)
			}, "75s", "15s").Should(BeZero())
		})
		It("restarts the old server and it becomes ready", func() {
			Expect(docker.RestartCluster(tc.Servers[:1])).To(Succeed())
			Eventually(func() error {
				return nodeReady(oldName)
			}, "180s", "5s").Should(Succeed())
			Expect(logCount(tc.Servers[0], "illegal base64")).To(BeZero())
		})
	})

	Context("Upgrade the old server", func() {
		It("runs the new build and sets the annotation", func() {
			current, err := os.ReadFile(artifact)
			Expect(err).NotTo(HaveOccurred())
			src := filepath.Join(GinkgoT().TempDir(), "k3s-upgrade")
			Expect(os.WriteFile(src, current, 0755)).To(Succeed())
			_, err = tests.RunCommand(fmt.Sprintf("docker cp %s %s:/root/k3s-upgrade", src, oldName))
			Expect(err).NotTo(HaveOccurred())
			sum, err := tc.Servers[0].RunCmdOnNode("sha256sum /root/k3s-upgrade | cut -d' ' -f1")
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.TrimSpace(sum)).To(Equal(fmt.Sprintf("%x", sha256.Sum256(current))))
			// the container still mounts the old inode, so this replaces the old build in place once k3s has stopped
			cmd := "systemctl stop k3s; /usr/local/bin/k3s-killall.sh; cat /root/k3s-upgrade > /usr/local/bin/k3s; systemctl start k3s"
			_, err = tc.Servers[0].RunCmdOnNode(cmd)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() error {
				return nodeReady(oldName)
			}, "180s", "5s").Should(Succeed())
			Eventually(func() string {
				return annotation(oldName)
			}, "120s", "5s").ShouldNot(BeEmpty())
		})
		It("rewrites the bootstrap data once every server carries the annotation", func() {
			Eventually(func() int {
				return logCount(tc.Servers[0], migrated) + logCount(tc.Servers[1], migrated)
			}, "180s", "10s").Should(BeNumerically(">", 0))
		})
		It("restarts both servers and they become ready", func() {
			Expect(docker.RestartCluster(tc.Servers)).To(Succeed())
			Eventually(func() error {
				return tests.NodesReady(tc.KubeconfigFile, tc.GetNodeNames())
			}, "240s", "5s").Should(Succeed())
		})
	})
})

var failed bool
var _ = AfterEach(func() {
	failed = failed || CurrentSpecReport().Failed()
})

var _ = AfterSuite(func() {
	if failed {
		AddReportEntry("journald-logs", docker.TailJournalLogs(1000, tc.Servers))
	}
	if tc != nil && (*ci || !failed) {
		Expect(tc.Cleanup()).To(Succeed())
	}
})
