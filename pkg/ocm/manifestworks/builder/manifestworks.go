/*
Copyright 2022 The KCP Authors.

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

package builder

import (
	"time"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apiserver/pkg/authentication/user"
	rbacinformers "k8s.io/client-go/informers/rbac/v1"

	//workinformer "open-cluster-management.io/api/client/work/informers/externalversions/work/v1"
	frameworkrbac "github.com/kcp-dev/kcp/pkg/virtual/framework/rbac"

	manifestworkauth "open-cluster-management.io/ocm-virtual-workspace/pkg/ocm/manifestworks/authorization"
	"open-cluster-management.io/ocm-virtual-workspace/pkg/ocm/manifestworks/registry"

	workinformer "open-cluster-management.io/api/client/work/informers/externalversions/work/v1"
	workapiv1 "open-cluster-management.io/api/work/v1"

	"github.com/kcp-dev/logicalcluster"
)

var _ registry.FilteredManifestWorkWorkspace = &authCacheManifestWorks{}

// authCacheClusterWorkspaces implement registry.FilteredClusterWorkspaces using an
// authorization cache.
type authCacheManifestWorks struct {
	// workspaceLister can enumerate workspace lists that enforce policy
	manifestWorkLister manifestworkauth.Lister
	// authCache is a cache of cluster workspaces and associated subjects for a given org.
	authCache *manifestworkauth.AuthorizationCache
	// stopCh allows stopping the authCache for this org.
	stopCh chan struct{}
}

// CreateAndStartOrg creates an Org that contains all the required clients and caches to retrieve user workspaces inside an org
// As part of an Org, a WorkspaceAuthCache is created and ensured to be started.
func CreateAndStartManifestWorkWorkspace(
	lclusterName logicalcluster.Name,
	rbacInformers rbacinformers.Interface,
	manifestWorkInformer workinformer.ManifestWorkInformer,
	initialWatchers []manifestworkauth.CacheWatcher,
) *authCacheManifestWorks {
	authCache := manifestworkauth.NewAuthorizationCache(
		lclusterName,
		manifestWorkInformer.Lister(),
		manifestWorkInformer.Informer(),
		manifestworkauth.NewReviewer(frameworkrbac.NewSubjectLocator(rbacInformers)),
		*manifestworkauth.NewAttributesBuilder().
			Verb("get").
			Resource(workapiv1.SchemeGroupVersion.WithResource("manifestworks")).
			AttributesRecord,
		rbacInformers,
	)

	cws := &authCacheManifestWorks{
		manifestWorkLister: authCache,
		stopCh:             make(chan struct{}),
		authCache:          authCache,
	}

	for _, watcher := range initialWatchers {
		authCache.AddWatcher(watcher)
	}

	cws.authCache.Run(1*time.Second, cws.stopCh)

	return cws
}

func (o *authCacheManifestWorks) List(user user.Info, labelSelector labels.Selector, fieldSelector fields.Selector) (*workapiv1.ManifestWorkList, error) {
	return o.manifestWorkLister.List(user, labelSelector, fieldSelector)
}

func (o *authCacheManifestWorks) RemoveWatcher(watcher manifestworkauth.CacheWatcher) {
	o.authCache.RemoveWatcher(watcher)
}

func (o *authCacheManifestWorks) AddWatcher(watcher manifestworkauth.CacheWatcher) {
	o.authCache.AddWatcher(watcher)
}

func (o *authCacheManifestWorks) Ready() bool {
	return o.authCache.ReadyForAccess()
}

func (o *authCacheManifestWorks) Stop() {
	o.stopCh <- struct{}{}
}
