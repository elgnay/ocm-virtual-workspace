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

package builder

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kcp-dev/logicalcluster"

	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	rbacinformers "k8s.io/client-go/informers/rbac/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	tenancyv1alpha1 "github.com/kcp-dev/kcp/pkg/apis/tenancy/v1alpha1"
	tenancyv1beta1 "github.com/kcp-dev/kcp/pkg/apis/tenancy/v1beta1"
	kcpclient "github.com/kcp-dev/kcp/pkg/client/clientset/versioned"
	workspaceinformer "github.com/kcp-dev/kcp/pkg/client/informers/externalversions/tenancy/v1alpha1"
	kcpopenapi "github.com/kcp-dev/kcp/pkg/openapi"
	"github.com/kcp-dev/kcp/pkg/virtual/framework"
	"github.com/kcp-dev/kcp/pkg/virtual/framework/fixedgvs"
	frameworkrbac "github.com/kcp-dev/kcp/pkg/virtual/framework/rbac"
	rbacwrapper "github.com/kcp-dev/kcp/pkg/virtual/framework/wrappers/rbac"
	tenancywrapper "github.com/kcp-dev/kcp/pkg/virtual/framework/wrappers/tenancy"

	workspaceauth "open-cluster-management.io/ocm-virtual-workspace/pkg/ocm/workspaces/authorization"
	workspacecache "open-cluster-management.io/ocm-virtual-workspace/pkg/ocm/workspaces/cache"
	workspaceregistry "open-cluster-management.io/ocm-virtual-workspace/pkg/ocm/workspaces/registry"

	manifestworkauth "open-cluster-management.io/ocm-virtual-workspace/pkg/ocm/manifestworks/authorization"
	manifestworkbuilder "open-cluster-management.io/ocm-virtual-workspace/pkg/ocm/manifestworks/builder"
	manifestworkcache "open-cluster-management.io/ocm-virtual-workspace/pkg/ocm/manifestworks/cache"
	manifestworkregistry "open-cluster-management.io/ocm-virtual-workspace/pkg/ocm/manifestworks/registry"
	ocmworkspace "open-cluster-management.io/ocm-virtual-workspace/pkg/ocm/workspace"

	workclientset "open-cluster-management.io/api/client/work/clientset/versioned"
	manifestworkinformer "open-cluster-management.io/api/client/work/informers/externalversions/work/v1"
	ocmopenapi "open-cluster-management.io/api/openapi"
	workapiv1 "open-cluster-management.io/api/work/v1"

	common "k8s.io/kube-openapi/pkg/common"
)

const WorkspacesVirtualWorkspaceName string = "ocm"

func BuildVirtualWorkspace(
	rootPathPrefix string,
	wildcardsClusterWorkspaces workspaceinformer.ClusterWorkspaceInformer,
	wildcardsRbacInformers rbacinformers.Interface,
	kubeClusterClient kubernetes.ClusterInterface,
	kcpClusterClient kcpclient.ClusterInterface,
	manifestWorkInformer manifestworkinformer.ManifestWorkInformer,
) framework.VirtualWorkspace {
	crbInformer := wildcardsRbacInformers.ClusterRoleBindings()
	_ = workspaceregistry.AddNameIndexers(crbInformer)

	if !strings.HasSuffix(rootPathPrefix, "/") {
		rootPathPrefix += "/"
	}

	// shared
	rootRBACInformers := rbacwrapper.FilterInformers(tenancyv1alpha1.RootCluster, wildcardsRbacInformers)
	rootSubjectLocator := frameworkrbac.NewSubjectLocator(rootRBACInformers)
	rootClusterWorkspaceInformer := tenancywrapper.FilterClusterWorkspaceInformer(tenancyv1alpha1.RootCluster, wildcardsClusterWorkspaces)

	// for workspaces only
	var rootWorkspaceAuthorizationCache *workspaceauth.AuthorizationCache
	var globalClusterWorkspaceCache *workspacecache.ClusterWorkspaceCache

	// for manifestworks
	var rootManifestWorkAuthorizationCache *manifestworkauth.AuthorizationCache
	var manifestWorkCache *manifestworkcache.ManifestWorkCache

	return &fixedgvs.FixedGroupVersionsVirtualWorkspace{
		Name: WorkspacesVirtualWorkspaceName,
		Ready: func() error {
			// workspaces
			if globalClusterWorkspaceCache == nil || !globalClusterWorkspaceCache.HasSynced() {
				return errors.New("ClusterWorkspaceCache is not ready for access")
			}

			if rootWorkspaceAuthorizationCache == nil || !rootWorkspaceAuthorizationCache.ReadyForAccess() {
				return errors.New("WorkspaceAuthorizationCache is not ready for access")
			}

			// manifestworks
			if manifestWorkCache == nil || !manifestWorkCache.HasSynced() {
				return errors.New("ManifestWorkCache is not ready for access")
			}
			if rootManifestWorkAuthorizationCache == nil || !rootManifestWorkAuthorizationCache.ReadyForAccess() {
				return errors.New("ManifestWorkAuthorizationCache is not ready for access")
			}

			return nil
		},
		RootPathResolver: func(urlPath string, requestContext context.Context) (accepted bool, prefixToStrip string, completedContext context.Context) {
			fmt.Printf("++++>RootPathResolver(): urlPath=%s\n", urlPath)

			completedContext = requestContext
			if !strings.HasPrefix(urlPath, rootPathPrefix) {
				return
			}

			withoutRootPathPrefix := strings.TrimPrefix(urlPath, rootPathPrefix)

			// Incoming requests to this virtual workspace will look like:
			//  /services/ocm/root:org:ws/<managed-cluster-name>/apis/work.open-cluster-management.io/v1/manifestworks
			//               └───────────────────────────┐
			// Where the withoutRootPathPrefix starts here: ┘
			segments := strings.SplitN(withoutRootPathPrefix, "/", 3)
			if len(segments) < 2 || segments[0] == "" || segments[1] == "" {
				return
			}
			org, managedCusterName := segments[0], segments[1]
			//fmt.Printf("++++>RootPathResolver(): org=%s\n", org)
			completedContext = context.WithValue(completedContext, ocmworkspace.ManagedClusterNameKey, managedCusterName)
			completedContext = context.WithValue(completedContext, ocmworkspace.WorkspaceNameKey, logicalcluster.New(org))

			parts := strings.SplitN(urlPath, "/namespaces/", 2)
			if len(parts) == 2 {
				strs := strings.SplitN(parts[1], "/", 2)
				if len(strs) > 0 {
					completedContext = context.WithValue(completedContext, ocmworkspace.NamespaceKey, strs[0])
				}
			}

			//fmt.Printf("++++>RootPathResolver(): org=%v\n", completedContext.Value(workspaceregistry.WorkspacesOrgKey))
			prefixToStrip = rootPathPrefix + strings.Join(segments[:2], "/")

			//fmt.Printf("++++>RootPathResolver(): prefixToStrip=%s\n", prefixToStrip)

			return true, prefixToStrip, completedContext
		},
		GroupVersionAPISets: []fixedgvs.GroupVersionAPISet{
			{
				GroupVersion:       tenancyv1beta1.SchemeGroupVersion,
				AddToScheme:        tenancyv1beta1.AddToScheme,
				OpenAPIDefinitions: kcpopenapi.GetOpenAPIDefinitions,
				BootstrapRestResources: func(mainConfig genericapiserver.CompletedConfig) (map[string]fixedgvs.RestStorageBuilder, error) {

					rootReviewer := workspaceauth.NewReviewer(rootSubjectLocator)
					globalClusterWorkspaceCache = workspacecache.NewClusterWorkspaceCache(wildcardsClusterWorkspaces.Informer(), kcpClusterClient)

					rootWorkspaceAuthorizationCache = workspaceauth.NewAuthorizationCache(
						rootClusterWorkspaceInformer.Lister(),
						rootClusterWorkspaceInformer.Informer(),
						rootReviewer,
						*workspaceauth.NewAttributesBuilder().
							Verb("access").
							Resource(tenancyv1alpha1.SchemeGroupVersion.WithResource("clusterworkspaces"), "content").
							AttributesRecord,
						rootRBACInformers,
					)

					orgListener := NewOrgListener(wildcardsClusterWorkspaces, func(orgClusterName logicalcluster.Name, initialWatchers []workspaceauth.CacheWatcher) workspaceregistry.FilteredClusterWorkspaces {
						return CreateAndStartOrg(
							rbacwrapper.FilterInformers(orgClusterName, wildcardsRbacInformers),
							tenancywrapper.FilterClusterWorkspaceInformer(orgClusterName, wildcardsClusterWorkspaces),
							initialWatchers)
					})

					if err := mainConfig.AddPostStartHook("clusterworkspaces.kcp.dev-workspaceauthorizationcache", func(context genericapiserver.PostStartHookContext) error {
						for _, informer := range []cache.SharedIndexInformer{
							wildcardsClusterWorkspaces.Informer(),
							wildcardsRbacInformers.ClusterRoleBindings().Informer(),
							wildcardsRbacInformers.RoleBindings().Informer(),
							wildcardsRbacInformers.ClusterRoles().Informer(),
							wildcardsRbacInformers.Roles().Informer(),
						} {
							if !cache.WaitForNamedCacheSync("workspaceauthorizationcache", context.StopCh, informer.HasSynced) {
								return errors.New("informer not synced")
							}
						}
						rootWorkspaceAuthorizationCache.Run(1*time.Second, context.StopCh)
						return nil
					}); err != nil {
						return nil, err
					}

					workspacesRest := workspaceregistry.NewREST(
						kcpClusterClient.Cluster(tenancyv1alpha1.RootCluster).TenancyV1alpha1(),
						kubeClusterClient,
						kcpClusterClient,
						globalClusterWorkspaceCache,
						crbInformer,
						orgListener.FilteredClusterWorkspaces)
					return map[string]fixedgvs.RestStorageBuilder{
						"workspaces": func(apiGroupAPIServerConfig genericapiserver.CompletedConfig) (rest.Storage, error) {
							return workspacesRest, nil
						},
					}, nil
				},
			},
			{
				GroupVersion:       workapiv1.SchemeGroupVersion,
				AddToScheme:        workapiv1.AddToScheme,
				OpenAPIDefinitions: compositeGetOpenAPIDefinitions,
				BootstrapRestResources: func(mainConfig genericapiserver.CompletedConfig) (map[string]fixedgvs.RestStorageBuilder, error) {
					manifestWorkCache = manifestworkcache.NewManifestWorkCache(manifestWorkInformer.Informer(),
						func(lclusterName logicalcluster.Name) (*workclientset.Clientset, error) {
							return nil, nil
						})
					workspaceListener := manifestworkbuilder.NewWorkspaceListener(wildcardsClusterWorkspaces, func(orgClusterName logicalcluster.Name, initialWatchers []manifestworkauth.CacheWatcher) manifestworkregistry.FilteredManifestWorkWorkspace {
						return manifestworkbuilder.CreateAndStartManifestWorkWorkspace(
							orgClusterName,
							rbacwrapper.FilterInformers(orgClusterName, wildcardsRbacInformers),
							manifestWorkInformer,
							initialWatchers)
					})
					if err := mainConfig.AddPostStartHook("clusterworkspaces.kcp.dev-manifestworkauthorizationcache", func(context genericapiserver.PostStartHookContext) error {
						for _, informer := range []cache.SharedIndexInformer{
							wildcardsClusterWorkspaces.Informer(),
							wildcardsRbacInformers.ClusterRoleBindings().Informer(),
							wildcardsRbacInformers.RoleBindings().Informer(),
							wildcardsRbacInformers.ClusterRoles().Informer(),
							wildcardsRbacInformers.Roles().Informer(),
							manifestWorkInformer.Informer(),
						} {
							if !cache.WaitForNamedCacheSync("manifestworkauthorizationcache", context.StopCh, informer.HasSynced) {
								return errors.New("informer not synced")
							}
						}
						return nil
					}); err != nil {
						return nil, err
					}

					manifestworksRest := manifestworkregistry.NewREST(
						manifestWorkCache,
						kubeClusterClient,
						workspaceListener.ManifestWorkWorkspaces,
					)
					return map[string]fixedgvs.RestStorageBuilder{
						"manifestworks": func(apiGroupAPIServerConfig genericapiserver.CompletedConfig) (rest.Storage, error) {
							return manifestworksRest, nil
						},
					}, nil
				},
			},
		},
	}
}

func compositeGetOpenAPIDefinitions(ref common.ReferenceCallback) map[string]common.OpenAPIDefinition {
	defs := kcpopenapi.GetOpenAPIDefinitions(ref)
	for k, v := range ocmopenapi.GetOpenAPIDefinitions(ref) {
		defs[k] = v
	}

	return defs
}
