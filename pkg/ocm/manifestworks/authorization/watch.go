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

package authorization

import (
	"errors"
	"fmt"
	"sync"

	"github.com/kcp-dev/logicalcluster"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/authentication/user"
	kstorage "k8s.io/apiserver/pkg/storage"
	"k8s.io/klog/v2"

	manifestworkcache "open-cluster-management.io/ocm-virtual-workspace/pkg/ocm/manifestworks/cache"

	workapiv1 "open-cluster-management.io/api/work/v1"
)

type CacheWatcher interface {
	// GroupMembershipChanged is called serially for all changes for all watchers.  This method MUST NOT BLOCK.
	// The serial nature makes reasoning about the code easy, but if you block in this method you will doom all watchers.
	GroupMembershipChanged(namespace, name string, users, groups sets.String)
}

type WatchableCache interface {
	// RemoveWatcher removes a watcher
	RemoveWatcher(CacheWatcher)
	// List returns the set of workspace names the user has access to view
	List(userInfo user.Info, labelSelector labels.Selector, fieldSelector fields.Selector) (*workapiv1.ManifestWorkList, error)
}

// userWorkspaceWatcher converts notifications received from the WorkspaceAuthCache to
// watch events sent through a watch.Interface.
type manifestWorkWatcher struct {
	user user.Info

	// cacheIncoming is a buffered channel used for notification to watcher.  If the buffer fills up,
	// then the watcher will be removed and the connection will be broken.
	cacheIncoming chan watch.Event
	// cacheError is a cached channel that is put to serially.  In theory, only one item will
	// ever be placed on it.
	cacheError chan error

	// outgoing is the unbuffered `ResultChan` use for the watch.  Backups of this channel will block
	// the default `emit` call.  That's why cacheError is a buffered channel.
	outgoing chan watch.Event
	// userStop lets a user stop his watch.
	userStop chan struct{}

	// stopLock keeps parallel stops from doing crazy things
	stopLock sync.Mutex

	// Injectable for testing. Send the event down the outgoing channel.
	emit func(watch.Event)

	manifestWorkCache *manifestworkcache.ManifestWorkCache
	authCache         WatchableCache

	initialManifestWorks []workapiv1.ManifestWork
	// knownWorkspaces maps name to resourceVersion
	knownManifestWorks map[string]string

	lclusterName logicalcluster.Name
}

var (
	// watchChannelHWM tracks how backed up the most backed up channel got.  This mirrors etcd watch behavior and allows tuning
	// of channel depth.
	watchChannelHWM kstorage.HighWaterMark
)

func NewUserWorkspaceWatcher(user user.Info, lclusterName logicalcluster.Name, manifestWorkCache *manifestworkcache.ManifestWorkCache, authCache WatchableCache, includeAllExistingManifestWorks bool, predicate kstorage.SelectionPredicate) *manifestWorkWatcher {
	manifestworks, _ := authCache.List(user, labels.Everything(), fields.Everything())
	knownManifestWorks := map[string]string{}
	for _, manifestwork := range manifestworks.Items {
		key := fmt.Sprintf("%s/%s", manifestwork.Namespace, manifestwork.Name)
		knownManifestWorks[key] = manifestwork.ResourceVersion
	}

	// this is optional.  If they don't request it, don't include it.
	initialManifestWorks := []workapiv1.ManifestWork{}
	if includeAllExistingManifestWorks {
		initialManifestWorks = append(initialManifestWorks, manifestworks.Items...)
	}

	w := &manifestWorkWatcher{
		user: user,

		cacheIncoming: make(chan watch.Event, 1000),
		cacheError:    make(chan error, 1),
		outgoing:      make(chan watch.Event),
		userStop:      make(chan struct{}),

		manifestWorkCache:    manifestWorkCache,
		authCache:            authCache,
		initialManifestWorks: initialManifestWorks,
		knownManifestWorks:   knownManifestWorks,

		lclusterName: lclusterName,
	}
	w.emit = func(e watch.Event) {
		// if dealing with workspace events, ensure that we only emit events for workspaces
		// that match the field or label selector specified by a consumer
		if manifestwork, ok := e.Object.(*workapiv1.ManifestWork); ok {
			if matches, err := predicate.Matches(manifestwork); err != nil || !matches {
				return
			}
		}

		select {
		case w.outgoing <- e:
		case <-w.userStop:
		}
	}
	return w
}

func projectManifestWork(manifestWork *workapiv1.ManifestWork) (*workapiv1.ManifestWork, error) {
	return manifestWork.DeepCopy(), nil
}

func (w *manifestWorkWatcher) GroupMembershipChanged(namespace, name string, users, groups sets.String) {
	hasAccess := users.Has(w.user.GetName()) || groups.HasAny(w.user.GetGroups()...)
	key := fmt.Sprintf("%s/%s", namespace, name)
	_, known := w.knownManifestWorks[key]

	manifestWork, err := w.manifestWorkCache.Get(w.lclusterName, namespace, name)
	if err != nil {
		utilruntime.HandleError(err)
		return
	}

	manifestWork, err = projectManifestWork(manifestWork)
	if err != nil {
		utilruntime.HandleError(err)
		return
	}

	switch {
	// this means that we were removed from the workspace
	case !hasAccess && known:
		delete(w.knownManifestWorks, key)

		select {
		case w.cacheIncoming <- watch.Event{
			Type:   watch.Deleted,
			Object: manifestWork,
		}:
		default:
			// remove the watcher so that we wont' be notified again and block
			w.authCache.RemoveWatcher(w)
			w.cacheError <- errors.New("delete notification timeout")
		}

	case hasAccess:
		event := watch.Event{
			Type:   watch.Added,
			Object: manifestWork,
		}

		// if we already have this in our list, then we're getting notified because the object changed
		if lastResourceVersion, known := w.knownManifestWorks[key]; known {
			event.Type = watch.Modified

			// if we've already notified for this particular resourceVersion, there's no work to do
			if lastResourceVersion == manifestWork.ResourceVersion {
				return
			}
		}
		w.knownManifestWorks[key] = manifestWork.ResourceVersion

		select {
		case w.cacheIncoming <- event:
		default:
			// remove the watcher so that we won't be notified again and block
			w.authCache.RemoveWatcher(w)
			w.cacheError <- errors.New("add notification timeout")
		}
	}
}

// Watch pulls stuff from etcd, converts, and pushes out the outgoing channel. Meant to be
// called as a goroutine.
func (w *manifestWorkWatcher) Watch() {
	defer close(w.outgoing)
	defer func() {
		// when the watch ends, always remove the watcher from the cache to avoid leaking.
		w.authCache.RemoveWatcher(w)
	}()
	defer utilruntime.HandleCrash()

	// start by emitting all the `initialWorkspaces`
	for i := range w.initialManifestWorks {
		// keep this check here to sure we don't keep this open in the case of failures
		select {
		case err := <-w.cacheError:
			w.emit(makeErrorEvent(err))
			return
		default:
		}
		manifestWork, _ := projectManifestWork(&w.initialManifestWorks[i])
		w.emit(watch.Event{
			Type:   watch.Added,
			Object: manifestWork,
		})
	}

	for {
		select {
		case err := <-w.cacheError:
			w.emit(makeErrorEvent(err))
			return

		case <-w.userStop:
			return

		case event := <-w.cacheIncoming:
			if curLen := int64(len(w.cacheIncoming)); watchChannelHWM.Update(curLen) {
				// Monitor if this gets backed up, and how much.
				klog.V(2).Infof("watch: %v objects queued in manifestwork cache watching channel.", curLen)
			}

			w.emit(event)
		}
	}
}

func makeErrorEvent(err error) watch.Event {
	return watch.Event{
		Type: watch.Error,
		Object: &metav1.Status{
			Status:  metav1.StatusFailure,
			Message: err.Error(),
		},
	}
}

// ResultChan implements watch.Interface.
func (w *manifestWorkWatcher) ResultChan() <-chan watch.Event {
	return w.outgoing
}

// Stop implements watch.Interface.
func (w *manifestWorkWatcher) Stop() {
	// lock access so we don't race past the channel select
	w.stopLock.Lock()
	defer w.stopLock.Unlock()

	// Prevent double channel closes.
	select {
	case <-w.userStop:
		return
	default:
	}
	close(w.userStop)
}
