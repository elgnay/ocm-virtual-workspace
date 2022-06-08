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
	"sync"

	"github.com/kcp-dev/logicalcluster"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	tenancyv1alpha1 "github.com/kcp-dev/kcp/pkg/apis/tenancy/v1alpha1"
	workspaceinformer "github.com/kcp-dev/kcp/pkg/client/informers/externalversions/tenancy/v1alpha1"
	listerstenancyv1alpha1 "github.com/kcp-dev/kcp/pkg/client/listers/tenancy/v1alpha1"

	"open-cluster-management.io/ocm-virtual-workspace/pkg/ocm/manifestworks/authorization"
	"open-cluster-management.io/ocm-virtual-workspace/pkg/ocm/manifestworks/registry"

	workapiv1 "open-cluster-management.io/api/work/v1"
)

type Stoppable interface {
	Stop()
}

// orgListener *-watches ClusterWorkspaces and starts virtualworkspacesregistry.Org for the
// parents for those. This means that workspaces without any ClusterWorkspace (like universal
// workspaces) will not be started.
type workspaceListener struct {
	lister   listerstenancyv1alpha1.ClusterWorkspaceLister
	informer cache.SharedIndexInformer

	newManifestWorkWorkspace func(orgClusterName logicalcluster.Name, initialWatchers []authorization.CacheWatcher) registry.FilteredManifestWorkWorkspace

	lock sync.RWMutex

	manifestWorkWorkspaces map[logicalcluster.Name]*preCreationManifestWorkWorkspace
}

func NewWorkspaceListener(informer workspaceinformer.ClusterWorkspaceInformer, newManifestWorkWorkspace func(orgClusterName logicalcluster.Name, initialWatchers []authorization.CacheWatcher) registry.FilteredManifestWorkWorkspace) *workspaceListener {
	l := &workspaceListener{
		lister:   informer.Lister(),
		informer: informer.Informer(),

		newManifestWorkWorkspace: newManifestWorkWorkspace,
		manifestWorkWorkspaces:   map[logicalcluster.Name]*preCreationManifestWorkWorkspace{},
	}

	// nolint: errcheck
	informer.Informer().AddIndexers(cache.Indexers{
		"parent": indexByLogicalCluster,
	})

	informer.Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    l.addClusterWorkspace,
			DeleteFunc: l.deleteClusterWorkspace,
		},
	)

	l.addClusterWorkspace(&tenancyv1alpha1.ClusterWorkspace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "root",
		},
	})

	return l
}

func (l *workspaceListener) Stop() {
	l.lock.RLock()
	defer l.lock.RUnlock()

	for _, o := range l.manifestWorkWorkspaces {
		o.Stop()
	}
}

func (l *workspaceListener) ListWorkspaceNames() []logicalcluster.Name {
	names := []logicalcluster.Name{}

	for k := range l.manifestWorkWorkspaces {
		names = append(names, k)
	}

	return names
}

func (l *workspaceListener) ManifestWorkWorkspaces() []registry.FilteredManifestWorkWorkspace {
	workspaces := []registry.FilteredManifestWorkWorkspace{}
	for _, v := range l.manifestWorkWorkspaces {
		workspaces = append(workspaces, v)
	}
	return workspaces
}

// FilteredClusterWorkspaces returns the cluster workspace provider or nil if it is started (does not mean it does
// not exist, we just don't know here).
// Note: because the defining ClusterWorkspace of the parent can be on a different shard, we cannot know here.
func (l *workspaceListener) FilteredManifestWorkWorkspace(orgName logicalcluster.Name) registry.FilteredManifestWorkWorkspace {
	// fast path
	l.lock.RLock()
	cws, found := l.manifestWorkWorkspaces[orgName]
	l.lock.RUnlock()
	if found {
		return cws
	}

	// slow path
	l.lock.Lock()
	defer l.lock.Unlock()
	if _, found := l.manifestWorkWorkspaces[orgName]; found {
		return cws
	}

	l.manifestWorkWorkspaces[orgName] = &preCreationManifestWorkWorkspace{}
	return l.manifestWorkWorkspaces[orgName]
}

func (l *workspaceListener) addClusterWorkspace(obj interface{}) {
	cw, ok := obj.(*tenancyv1alpha1.ClusterWorkspace)
	if !ok {
		klog.Errorf("expected ClusterWorkspace but handler received %#v", obj)
		return
	}

	// fast path
	workspace := logicalcluster.From(cw).Join(cw.Name)
	l.lock.RLock()
	cws, found := l.manifestWorkWorkspaces[workspace]
	if found {
		cws.lock.RLock()
		if cws.delegate != nil {
			cws.lock.RUnlock()
			l.lock.RUnlock()
			return
		}
		cws.lock.RUnlock()
	}
	l.lock.RUnlock()

	// slow path
	l.lock.Lock()
	defer l.lock.Unlock()
	cws, found = l.manifestWorkWorkspaces[workspace]
	var existingWatchers []authorization.CacheWatcher
	if found {
		cws.lock.RLock()
		if cws.delegate != nil {
			cws.lock.RUnlock()
			return
		}
		cws.lock.RUnlock()

		// there is no auth cache running yet. Start one.
		cws.lock.Lock()
		defer cws.lock.Unlock()
		existingWatchers = cws.watchers
		cws.watchers = nil
	} else {
		cws = &preCreationManifestWorkWorkspace{}
		l.manifestWorkWorkspaces[workspace] = cws
	}

	klog.Infof("First ManifestWorkWorkspace for %s, starting authorization cache", workspace)
	l.manifestWorkWorkspaces[workspace].delegate = l.newManifestWorkWorkspace(workspace, existingWatchers)
}

func (l *workspaceListener) deleteClusterWorkspace(obj interface{}) {
	cw, ok := obj.(*tenancyv1alpha1.ClusterWorkspace)
	if !ok {
		klog.Errorf("Expected ClusterWorkspace but handler received %#v", obj)
		return
	}

	// fast path
	workspace := logicalcluster.From(cw).Join(cw.Name)
	l.lock.RLock()
	_, found := l.manifestWorkWorkspaces[workspace]
	l.lock.RUnlock()
	if !found {
		return
	}

	// any other ClusterWorkspace in this logical cluster?
	others, err := l.informer.GetIndexer().ByIndex("parent", workspace.String())
	if err != nil {
		klog.Errorf("Failed to get ClusterWorkspace parent index %v: %v", workspace, err)
		return
	}
	if len(others) > 0 {
		return
	}

	// slow path
	l.lock.Lock()
	defer l.lock.Unlock()
	cws, found := l.manifestWorkWorkspaces[workspace]
	if !found {
		return
	}

	klog.Infof("Last ManifestWorkWorkspace for %s is gone", workspace)
	// Note: this will stop watches on last ClusterWorkspace removal. Not perfect, but ok.
	cws.Stop()
	delete(l.manifestWorkWorkspaces, workspace)
}

// preCreationManifestWorks is a proxy object that collects watchers before the actual auth cache is started.
// On auth cache start, the collected watchers are added to the auth cache.
type preCreationManifestWorkWorkspace struct {
	lock     sync.RWMutex
	watchers []authorization.CacheWatcher
	delegate registry.FilteredManifestWorkWorkspace
}

func (cws *preCreationManifestWorkWorkspace) List(user user.Info, labelSelector labels.Selector, fieldSelector fields.Selector) (*workapiv1.ManifestWorkList, error) {
	cws.lock.RLock()
	defer cws.lock.RUnlock()
	if cws.delegate != nil {
		return cws.delegate.List(user, labelSelector, fieldSelector)
	}
	return &workapiv1.ManifestWorkList{}, nil
}

func (cws *preCreationManifestWorkWorkspace) RemoveWatcher(watcher authorization.CacheWatcher) {
	// fast path
	cws.lock.RLock()
	if cws.delegate != nil {
		cws.delegate.RemoveWatcher(watcher)
		cws.lock.RUnlock()
		return
	}
	cws.lock.RUnlock()

	// slow path
	cws.lock.Lock()
	defer cws.lock.Unlock()
	if cws.delegate != nil {
		cws.delegate.RemoveWatcher(watcher)
		return
	}

	for i, w := range cws.watchers {
		if w == watcher {
			cws.watchers = append(cws.watchers[:i], cws.watchers[i+1:]...)
			return
		}
	}
}

func (cws *preCreationManifestWorkWorkspace) AddWatcher(watcher authorization.CacheWatcher) {
	// fast path
	cws.lock.RLock()
	if cws.delegate != nil {
		cws.delegate.AddWatcher(watcher)
		cws.lock.RUnlock()
		return
	}
	cws.lock.RUnlock()

	// slow path
	cws.lock.Lock()
	defer cws.lock.Unlock()
	if cws.delegate != nil {
		cws.delegate.AddWatcher(watcher)
		return
	}
	cws.watchers = append(cws.watchers, watcher)
}

func (cws *preCreationManifestWorkWorkspace) Stop() {
	cws.lock.Lock()
	defer cws.lock.Unlock()
	for _, w := range cws.watchers {
		if w, ok := w.(Stoppable); ok {
			w.Stop()
		}
	}
}
