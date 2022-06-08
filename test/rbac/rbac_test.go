package rbac

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	rbacauthorizer "k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac"

	frameworkrbac "github.com/kcp-dev/kcp/pkg/virtual/framework/rbac"
	rbacwrapper "github.com/kcp-dev/kcp/pkg/virtual/framework/wrappers/rbac"
	"github.com/kcp-dev/logicalcluster"
	workspaceregistry "open-cluster-management.io/ocm-virtual-workspace/pkg/ocm/workspaces/registry"

	workapiv1 "open-cluster-management.io/api/work/v1"
)

var _ = ginkgo.Describe("RBAC", ginkgo.Ordered, func() {
	var stop context.CancelFunc
	var subjectLocator rbacauthorizer.SubjectLocator
	ginkgo.BeforeAll(func() {
		kubeClientConfig := rest.CopyConfig(restConfig)
		u, err := url.Parse(kubeClientConfig.Host)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		u.Path = ""
		kubeClientConfig.Host = u.String()

		kubeClusterClient, err := kubernetes.NewClusterForConfig(kubeClientConfig)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		wildcardKubeClient := kubeClusterClient.Cluster(logicalcluster.Wildcard)
		wildcardKubeInformers := kubeinformers.NewSharedInformerFactory(wildcardKubeClient, 10*time.Minute)
		wildcardsRbacInformers := wildcardKubeInformers.Rbac().V1()

		crbInformer := wildcardsRbacInformers.ClusterRoleBindings()
		_ = workspaceregistry.AddNameIndexers(crbInformer)

		rootRBACInformers := rbacwrapper.FilterInformers(logicalcluster.New("root"), wildcardsRbacInformers)
		subjectLocator = frameworkrbac.NewSubjectLocator(rootRBACInformers)

		var ctx context.Context
		ctx, stop = context.WithCancel(context.Background())
		wildcardKubeInformers.Start(ctx.Done())
	})

	ginkgo.AfterAll(func() {
		if stop != nil {
			stop()
		}
	})

	ginkgo.It("SubjectLocator", func() {
		user := &user.DefaultInfo{
			Name: "alex",
			UID:  "alex",
		}

		attr := authorizer.AttributesRecord{
			User:            user,
			Verb:            "get",
			APIGroup:        workapiv1.SchemeGroupVersion.Group,
			APIVersion:      workapiv1.SchemeGroupVersion.Version,
			Resource:        "manifestworks",
			Name:            "work1",
			ResourceRequest: true,
		}

		gomega.Eventually(func() error {
			subjects, err := subjectLocator.AllowedSubjects(attr)
			if err != nil {
				return err
			}
			names := sets.NewString()
			fmt.Printf("++++> %d subjects found.\n", len(subjects))
			for _, subject := range subjects {
				names.Insert(subject.Name)
				fmt.Printf("    ++++>subjects=%s\n", subject.Name)
			}
			if !names.Has("alex") {
				return fmt.Errorf("subject %s not allowed", "alex")
			}
			return nil
		}, 30, 2).Should(gomega.Succeed())
	})
})
