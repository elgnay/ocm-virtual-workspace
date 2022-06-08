/*
Copyright 2021 The KCP Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package util

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic"
	apistorage "k8s.io/apiserver/pkg/storage"

	workspaceapiv1alpha1 "github.com/kcp-dev/kcp/pkg/apis/tenancy/v1alpha1"
	workspaceapiv1beta1 "github.com/kcp-dev/kcp/pkg/apis/tenancy/v1beta1"
	"github.com/kcp-dev/logicalcluster"
)

// getAttrs returns labels and fields of a given object for filtering purposes.
func getAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	switch workspaceObj := obj.(type) {
	case *workspaceapiv1beta1.Workspace:
		return labels.Set(workspaceObj.Labels), workspaceToSelectableFields(workspaceObj), nil
	case *workspaceapiv1alpha1.ClusterWorkspace:
		return labels.Set(workspaceObj.Labels), clusterWorkspaceToSelectableFields(workspaceObj), nil
	default:
		return nil, nil, fmt.Errorf("not a workspace")
	}
}

// MatchWorkspace returns a generic matcher for a given label and field selector.
func MatchWorkspace(label labels.Selector, field fields.Selector) apistorage.SelectionPredicate {
	return apistorage.SelectionPredicate{
		Label:    label,
		Field:    field,
		GetAttrs: getAttrs,
	}
}

// workspaceToSelectableFields returns a field set that represents the object
func workspaceToSelectableFields(workspaceObj *workspaceapiv1beta1.Workspace) fields.Set {
	objectMetaFieldsSet := generic.ObjectMetaFieldsSet(&workspaceObj.ObjectMeta, false)
	specificFieldsSet := fields.Set{
		"status.phase": string(workspaceObj.Status.Phase),
	}
	return generic.MergeFieldsSets(objectMetaFieldsSet, specificFieldsSet)
}

// clusterWorkspaceToSelectableFields returns a field set that represents the object
func clusterWorkspaceToSelectableFields(workspaceObj *workspaceapiv1alpha1.ClusterWorkspace) fields.Set {
	objectMetaFieldsSet := generic.ObjectMetaFieldsSet(&workspaceObj.ObjectMeta, false)
	specificFieldsSet := fields.Set{
		"status.phase": string(workspaceObj.Status.Phase),
	}
	return generic.MergeFieldsSets(objectMetaFieldsSet, specificFieldsSet)
}

func ToClusterAwareKey(clusterName logicalcluster.Name, namespace, name string) string {
	if !clusterName.Empty() {
		return namespace + "/" + clusterName.String() + "#$#" + name
	}

	return name
}

// SplitClusterAwareKey just allows extract the name and clusterName
// from a Key initially created with ToClusterAwareKey
func SplitClusterAwareKey(clusterAwareKey string) (clusterName logicalcluster.Name, namespace, name string) {
	segments := strings.SplitN(clusterAwareKey, "/", 2)
	if len(segments) == 0 {
		name = segments[0]
	} else {
		namespace = segments[0]
		name = segments[1]
	}

	parts := strings.SplitN(name, "#$#", 2)
	if len(parts) == 1 {
		// name only, no cluster
		return logicalcluster.Name{}, namespace, parts[0]
	}
	// clusterName and name
	return logicalcluster.New(parts[0]), namespace, parts[1]
}
