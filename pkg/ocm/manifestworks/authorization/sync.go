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

package authorization

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
	rbacv1listers "k8s.io/client-go/listers/rbac/v1"

	workapiv1 "open-cluster-management.io/api/work/v1"
)

// Lister enforces ability to enumerate a resource based on role
type Lister interface {
	// List returns the list of ClusterWorkspace items that the user can access
	List(user user.Info, labelSelector labels.Selector, fieldSelector fields.Selector) (*workapiv1.ManifestWorkList, error)
}

// subjectRecord is a cache record for the set of workspaces a subject can access
type subjectRecord struct {
	subject string
	keys    sets.String
}

// reviewRequest is the resource we want to review
type reviewRequest struct {
	key string
	// the resource version of the workspace that was observed to make this request
	resourceVersion string
	// the map of role uid to resource version that was observed to make this request
	clusterRoleUIDToResourceVersion map[types.UID]string
	// the map of role binding uid to resource version that was observed to make this request
	clusterRoleBindingUIDToResourceVersion map[types.UID]string

	// the map of role uid to resource version that was observed to make this request
	roleUIDToResourceVersion map[types.UID]string
	// the map of role binding uid to resource version that was observed to make this request
	roleBindingUIDToResourceVersion map[types.UID]string
}

// reviewRecord is a cache record for the result of a resource access review
type reviewRecord struct {
	*reviewRequest
	users  []string
	groups []string
}

// reviewRecordKeyFn is a key func for reviewRecord objects
func reviewRecordKeyFn(obj interface{}) (string, error) {
	reviewRecord, ok := obj.(*reviewRecord)
	if !ok {
		return "", fmt.Errorf("expected reviewRecord")
	}
	return reviewRecord.key, nil
}

// subjectRecordKeyFn is a key func for subjectRecord objects
func subjectRecordKeyFn(obj interface{}) (string, error) {
	subjectRecord, ok := obj.(*subjectRecord)
	if !ok {
		return "", fmt.Errorf("expected subjectRecord")
	}
	return subjectRecord.subject, nil
}

type skipSynchronizer interface {
	// SkipSynchronize returns true if if its safe to skip synchronization of the cache based on provided token from previous observation
	SkipSynchronize(prevState string, versionedObjects ...LastSyncResourceVersioner) (skip bool, currentState string)
}

// LastSyncResourceVersioner is any object that can divulge a LastSyncResourceVersion
type LastSyncResourceVersioner interface {
	LastSyncResourceVersion() string
}

type unionLastSyncResourceVersioner []LastSyncResourceVersioner

func (u unionLastSyncResourceVersioner) LastSyncResourceVersion() string {
	resourceVersions := []string{}
	for _, versioner := range u {
		resourceVersions = append(resourceVersions, versioner.LastSyncResourceVersion())
	}
	return strings.Join(resourceVersions, "")
}

type statelessSkipSynchronizer struct{}

func (rs *statelessSkipSynchronizer) SkipSynchronize(prevState string, versionedObjects ...LastSyncResourceVersioner) (skip bool, currentState string) {
	//fmt.Printf("++++>statelessSkipSynchronizer.SkipSynchronize(): prevState=%s\n", prevState)
	resourceVersions := []string{}
	for i := range versionedObjects {
		resourceVersions = append(resourceVersions, versionedObjects[i].LastSyncResourceVersion())
	}
	currentState = strings.Join(resourceVersions, ",")
	//fmt.Printf("++++>statelessSkipSynchronizer.SkipSynchronize(): currentState=%s\n", currentState)
	skip = currentState == prevState

	return skip, currentState
}

type neverSkipSynchronizer struct{}

func (s *neverSkipSynchronizer) SkipSynchronize(prevState string, versionedObjects ...LastSyncResourceVersioner) (bool, string) {
	return false, ""
}

type SyncedClusterRoleLister interface {
	rbacv1listers.ClusterRoleLister
	LastSyncResourceVersioner
}

type SyncedClusterRoleBindingLister interface {
	rbacv1listers.ClusterRoleBindingLister
	LastSyncResourceVersioner
}

type SyncedRoleLister interface {
	rbacv1listers.RoleLister
	LastSyncResourceVersioner
}

type SyncedRoleBindingLister interface {
	rbacv1listers.RoleBindingLister
	LastSyncResourceVersioner
}

type syncedClusterRoleLister struct {
	rbacv1listers.ClusterRoleLister
	versioner LastSyncResourceVersioner
}

func (l syncedClusterRoleLister) LastSyncResourceVersion() string {
	return l.versioner.LastSyncResourceVersion()
}

type syncedClusterRoleBindingLister struct {
	rbacv1listers.ClusterRoleBindingLister
	versioner LastSyncResourceVersioner
}

func (l syncedClusterRoleBindingLister) LastSyncResourceVersion() string {
	return l.versioner.LastSyncResourceVersion()
}

type syncedRoleLister struct {
	rbacv1listers.RoleLister
	versioner LastSyncResourceVersioner
}

func (l syncedRoleLister) LastSyncResourceVersion() string {
	return l.versioner.LastSyncResourceVersion()
}

type syncedRoleBindingLister struct {
	rbacv1listers.RoleBindingLister
	versioner LastSyncResourceVersioner
}

func (l syncedRoleBindingLister) LastSyncResourceVersion() string {
	return l.versioner.LastSyncResourceVersion()
}
