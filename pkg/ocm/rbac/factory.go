package rbac

import (
	rbacinformers "k8s.io/client-go/informers/rbac/v1"
	rbacauthorizer "k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac"

	frameworkrbac "github.com/kcp-dev/kcp/pkg/virtual/framework/rbac"
	rbacwrapper "github.com/kcp-dev/kcp/pkg/virtual/framework/wrappers/rbac"
	"github.com/kcp-dev/logicalcluster"
)

type SubjectLocatorFactory interface {
	GetSubjectLocator(clusterName logicalcluster.Name) rbacauthorizer.SubjectLocator
}

type subjectLocatorFactory struct {
	informers       rbacinformers.Interface
	subjectLocators map[logicalcluster.Name]rbacauthorizer.SubjectLocator
}

func (s *subjectLocatorFactory) GetSubjectLocator(clusterName logicalcluster.Name) rbacauthorizer.SubjectLocator {
	if subjectLocator, ok := s.subjectLocators[clusterName]; ok {
		return subjectLocator
	}

	clusterRBACInformers := rbacwrapper.FilterInformers(clusterName, s.informers)
	subjectLocator := frameworkrbac.NewSubjectLocator(clusterRBACInformers)
	s.subjectLocators[clusterName] = subjectLocator

	return subjectLocator
}

func NewSubjectLocatorFactory(informers rbacinformers.Interface) SubjectLocatorFactory {
	return &subjectLocatorFactory{
		informers:       informers,
		subjectLocators: map[logicalcluster.Name]rbacauthorizer.SubjectLocator{},
	}
}
