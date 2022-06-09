package projection

import (
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kcp-dev/logicalcluster"
	workapiv1 "open-cluster-management.io/api/work/v1"
)

func ProjectManifestWorks(list *workapiv1.ManifestWorkList) *workapiv1.ManifestWorkList {
	if list == nil {
		return nil
	}

	newList := &workapiv1.ManifestWorkList{}
	for _, work := range list.Items {
		newList.Items = append(newList.Items, ProjectManifestWork(work))
	}

	return newList
}

func ProjectManifestWork(work workapiv1.ManifestWork) workapiv1.ManifestWork {
	newWork := work.DeepCopy()
	clusterName := logicalcluster.From(&work)
	workspaceName := strings.ReplaceAll(clusterName.String(), ":", "-")
	newWork.Name = fmt.Sprintf("%s-%s", workspaceName, work.Name)
	newWork.Spec.Executor = &workapiv1.ManifestWorkExecutor{
		Subject: workapiv1.ManifestWorkExecutorSubject{
			Type: workapiv1.ExecutorSubjectTypeServiceAccount,
			ServiceAccount: &workapiv1.ManifestWorkSubjectServiceAccount{
				Namespace: "open-cluster-management-agent",
				Name:      workspaceName,
			},
		},
	}
	return *newWork
}

func ProjectedNamespacedName(obj metav1.Object) string {
	clusterName := logicalcluster.From(obj)
	workspaceName := strings.ReplaceAll(clusterName.String(), ":", "-")

	return fmt.Sprintf("%s/%s-%s", obj.GetNamespace(), workspaceName, obj.GetName())
}
