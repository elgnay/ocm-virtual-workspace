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

package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/kcp-dev/logicalcluster"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	klog "k8s.io/klog/v2"

	workclientset "open-cluster-management.io/api/client/work/clientset/versioned"
	workapiv1 "open-cluster-management.io/api/work/v1"
)

type GetWorkClient func(lclusterName logicalcluster.Name) (*workclientset.Clientset, error)

// NewClusterWorkspaceCache returns a wrapper around an informer. It serves from the informer, and on cache-miss
// it looks up through the given client.
func NewManifestWorkCache(manifestWorks cache.SharedIndexInformer, getWorkClient GetWorkClient) *ManifestWorkCache {
	// nolint: errcheck
	manifestWorks.AddIndexers(cache.Indexers{
		"PorjectedNamespcaedName": indexByPorjectedNamespcaedName,
	})
	return &ManifestWorkCache{
		GetWorkClient: getWorkClient,
		Store:         manifestWorks.GetIndexer(),
		HasSynced:     manifestWorks.GetController().HasSynced,
	}
}

type ManifestWorkCache struct {
	GetWorkClient GetWorkClient
	Store         cache.Indexer
	HasSynced     cache.InformerSynced
}

func (c *ManifestWorkCache) GetByProjectedNamespacedName(name string) ([]*workapiv1.ManifestWork, error) {
	others, err := c.Store.ByIndex("PorjectedNamespcaedName", name)
	if err != nil {
		return nil, err
	}

	var matched []*workapiv1.ManifestWork
	for _, object := range others {
		if work, ok := object.(*workapiv1.ManifestWork); ok {
			matched = append(matched, work)
		}
	}

	return matched, nil
}

func (c *ManifestWorkCache) Get(lclusterName logicalcluster.Name, namespace, name string) (*workapiv1.ManifestWork, error) {
	key := &workapiv1.ManifestWork{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, ClusterName: lclusterName.String()}}

	// check for cluster workspace in the cache
	manifestWorkObj, exists, err := c.Store.Get(key)
	if err != nil {
		return nil, err
	}

	if !exists {
		// give the cache time to observe a recent workspace creation
		time.Sleep(50 * time.Millisecond)
		manifestWorkObj, exists, err = c.Store.Get(key)
		if err != nil {
			return nil, err
		}
		if exists {
			klog.V(4).Infof("found %s/%s in cache after waiting", namespace, name)
		}
	}

	var manifestWork *workapiv1.ManifestWork
	if exists {
		manifestWork = manifestWorkObj.(*workapiv1.ManifestWork)
	} else {
		workClient, err := c.GetWorkClient(lclusterName)
		if err != nil {
			return nil, err
		}
		// Our watch maybe latent, so we make a best effort to get the object, and only fail if not found

		manifestWork, err = workClient.WorkV1().ManifestWorks(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		// the workspace does not exist, so prevent create and update in that workspace
		if err != nil {
			return nil, fmt.Errorf("manifestwork %s/%s does not exist", namespace, name)
		}
		klog.V(4).Infof("found %s/%s via storage lookup", namespace, name)
	}
	return manifestWork, nil
}
