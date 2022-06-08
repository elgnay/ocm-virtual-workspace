package rbac

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	kubeconfig = "/Users/leyan/workspaces/kcp/ocm-virtual-workspace/kubeconfig"
)

var (
	restConfig *rest.Config
)

func TestRbac(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Rbac Suite")
}

var _ = ginkgo.BeforeSuite(func() {
	var err error
	restConfig, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
})
