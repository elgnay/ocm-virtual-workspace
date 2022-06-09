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

package registry

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"unsafe"

	rbacv1 "k8s.io/api/rbac/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metainternal "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	rbacinformers "k8s.io/client-go/informers/rbac/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/printers"
	printerstorage "k8s.io/kubernetes/pkg/printers/storage"

	tenancyv1alpha1 "github.com/kcp-dev/kcp/pkg/apis/tenancy/v1alpha1"
	tenancyv1beta1 "github.com/kcp-dev/kcp/pkg/apis/tenancy/v1beta1"
	"github.com/kcp-dev/kcp/pkg/authorization/delegated"
	"github.com/kcp-dev/logicalcluster"
	manifestworkauth "open-cluster-management.io/ocm-virtual-workspace/pkg/ocm/manifestworks/authorization"
	manifestworkprinters "open-cluster-management.io/ocm-virtual-workspace/pkg/ocm/manifestworks/printers"
	"open-cluster-management.io/ocm-virtual-workspace/pkg/ocm/manifestworks/projection"
	ocmworkspace "open-cluster-management.io/ocm-virtual-workspace/pkg/ocm/workspace"

	workapiv1 "open-cluster-management.io/api/work/v1"

	//"open-cluster-management.io/ocm-virtual-workspace/pkg/ocm/common"
	manifestworkcache "open-cluster-management.io/ocm-virtual-workspace/pkg/ocm/manifestworks/cache"
)

const (
	PrettyNameLabel   string = "workspaces.kcp.dev/pretty-name"
	InternalNameLabel string = "workspaces.kcp.dev/internal-name"
	PrettyNameIndex   string = "workspace-pretty-name"
	InternalNameIndex string = "workspace-internal-name"
)

// FilteredManifestWorks allows to list and watch ManifestWorks
// filtered by authorizaation, i.e. a user only sees those object he has access to.
type FilteredManifestWorkWorkspace interface {
	manifestworkauth.Lister
	manifestworkauth.WatchableCache
	AddWatcher(watcher manifestworkauth.CacheWatcher)
	Stop()
}

type REST struct {
	// clusterWorkspaceCache is a global cache of cluster workspaces (for all orgs) used by the watcher.
	manifestworkCache *manifestworkcache.ManifestWorkCache

	// getFilteredClusterWorkspaces returns a provider for ClusterWorkspaces.
	getManifestWorkWorkspaces func() map[logicalcluster.Name]FilteredManifestWorkWorkspace

	kubeClusterClient kubernetes.ClusterInterface

	// delegatedAuthz implements cluster-aware SubjectAccessReview
	delegatedAuthz delegated.DelegatedAuthorizerFactory
	/*

		// crbInformer allows listing or searching for RBAC cluster role bindings through all orgs
		crbInformer rbacinformers.ClusterRoleBindingInformer


		kcpClusterClient  kcpclientset.ClusterInterface


		createStrategy rest.RESTCreateStrategy
		updateStrategy rest.RESTUpdateStrategy
	*/
	rest.TableConvertor
}

func AddNameIndexers(crbInformer rbacinformers.ClusterRoleBindingInformer) error {
	return crbInformer.Informer().AddIndexers(map[string]cache.IndexFunc{
		PrettyNameIndex: func(obj interface{}) ([]string, error) {
			if crb, isCRB := obj.(*rbacv1.ClusterRoleBinding); isCRB {
				return []string{lclusterAwareIndexValue(logicalcluster.From(crb), crb.Labels[PrettyNameLabel])}, nil
			}

			return []string{}, nil
		},
		InternalNameIndex: func(obj interface{}) ([]string, error) {
			if crb, isCRB := obj.(*rbacv1.ClusterRoleBinding); isCRB {
				return []string{lclusterAwareIndexValue(logicalcluster.From(crb), crb.Labels[InternalNameLabel])}, nil
			}

			return []string{}, nil
		},
	})
}

func lclusterAwareIndexValue(lclusterName logicalcluster.Name, indexValue string) string {
	return lclusterName.String() + "#$#" + indexValue
}

var _ rest.Lister = &REST{}

/*
var _ rest.Watcher = &REST{}
var _ rest.Scoper = &REST{}
var _ rest.Creater = &REST{}
var _ rest.GracefulDeleter = &REST{}
*/

// NewREST returns a RESTStorage object that will work against ClusterWorkspace resources in
// org workspaces, projecting them to the Workspace type.
func NewREST(
	manifestworkCache *manifestworkcache.ManifestWorkCache,
	kubeClusterClient kubernetes.ClusterInterface,
	/*
		rootTenancyClient tenancyclient.TenancyV1alpha1Interface,
		kcpClusterClient kcpclientset.ClusterInterface,
		wilcardsCRBInformer rbacinformers.ClusterRoleBindingInformer,
		getFilteredClusterWorkspaces func(orgClusterName logicalcluster.Name) FilteredClusterWorkspaces,
	*/
	getManifestWorkWorkspaces func() map[logicalcluster.Name]FilteredManifestWorkWorkspace,
) *REST {
	mainRest := &REST{
		manifestworkCache:         manifestworkCache,
		getManifestWorkWorkspaces: getManifestWorkWorkspaces,
		delegatedAuthz:            delegated.NewDelegatedAuthorizer,
		kubeClusterClient:         kubeClusterClient,
		/*
			getFilteredClusterWorkspaces: getFilteredClusterWorkspaces,


			kcpClusterClient:  kcpClusterClient,

			crbInformer: wilcardsCRBInformer,

			clusterWorkspaceCache: clusterWorkspaceCache,

			createStrategy: Strategy,
			updateStrategy: Strategy,
		*/

		TableConvertor: printerstorage.TableConvertor{TableGenerator: printers.NewTableGenerator().With(manifestworkprinters.AddManifestWorkPrintHandlers)},
	}

	return mainRest
}

// New returns a new ManifestWork
func (s *REST) New() runtime.Object {
	return &workapiv1.ManifestWork{}
}

// Destroy implements rest.Storage
func (s *REST) Destroy() {
	// Do nothing
}

// NewList returns a new ClusterWorkspaceList
func (*REST) NewList() runtime.Object {
	return &workapiv1.ManifestWorkList{}
}

func (s *REST) NamespaceScoped() bool {
	return true
}

/*
func (s *REST) getPrettyNameFromInternalName(user kuser.Info, orgClusterName logicalcluster.Name, internalName string) (string, error) {
	list, err := s.crbInformer.Informer().GetIndexer().ByIndex(InternalNameIndex, lclusterAwareIndexValue(orgClusterName, internalName))
	if err != nil {
		return "", err
	}
	for _, el := range list {
		if crb, isCRB := el.(*rbacv1.ClusterRoleBinding); isCRB &&
			len(crb.Subjects) == 1 && crb.Subjects[0].Name == user.GetName() {
			return crb.Labels[PrettyNameLabel], nil
		}
	}
	return "", kerrors.NewNotFound(tenancyv1beta1.Resource("workspaces"), internalName)
}

func (s *REST) getInternalNameFromPrettyName(user kuser.Info, orgClusterName logicalcluster.Name, prettyName string) (string, error) {
	list, err := s.crbInformer.Informer().GetIndexer().ByIndex(PrettyNameIndex, lclusterAwareIndexValue(orgClusterName, prettyName))
	if err != nil {
		return "", err
	}
	for _, el := range list {
		if crb, isCRB := el.(*rbacv1.ClusterRoleBinding); isCRB &&
			len(crb.Subjects) == 1 && crb.Subjects[0].Name == user.GetName() {
			return crb.Labels[InternalNameLabel], nil
		}
	}
	return "", kerrors.NewNotFound(tenancyv1beta1.Resource("workspaces"), prettyName)
}
*/
func (s *REST) authorizeWorkspaceForUser(ctx context.Context, clusterName logicalcluster.Name, user user.Info, verb string) error {
	// Root org access is implicit for every user. For non-root orgs, we need to check for
	// verb=access permissions against the clusterworkspaces/content of the ClusterWorkspace of
	// the org in the root.
	if clusterName == tenancyv1alpha1.RootCluster || sets.NewString(user.GetGroups()...).Has("system:masters") {
		return nil
	}

	parent, workspace := clusterName.Split()
	authz, err := s.delegatedAuthz(parent, s.kubeClusterClient)
	if err != nil {
		klog.Errorf("failed to get delegated authorizer for logical cluster %s", user.GetName(), parent)
		return kerrors.NewForbidden(tenancyv1beta1.Resource("workspaces"), workspace, fmt.Errorf("%q workspace access not permitted", parent))
	}
	typeUseAttr := authorizer.AttributesRecord{
		User:            user,
		Verb:            verb,
		APIGroup:        tenancyv1alpha1.SchemeGroupVersion.Group,
		APIVersion:      tenancyv1alpha1.SchemeGroupVersion.Version,
		Resource:        "clusterworkspaces",
		Subresource:     "content",
		Name:            workspace,
		ResourceRequest: true,
	}
	if decision, reason, err := authz.Authorize(ctx, typeUseAttr); err != nil {
		klog.Errorf("failed to authorize user %q to %q clusterworkspaces/content name %q in %s", user.GetName(), verb, workspace, parent)
		return kerrors.NewForbidden(tenancyv1beta1.Resource("workspaces"), workspace, fmt.Errorf("%q workspace access not permitted", clusterName))
	} else if decision != authorizer.DecisionAllow {
		klog.Errorf("user %q lacks (%s) clusterworkspaces/content %q permission for %q in %s: %s", user.GetName(), decisions[decision], verb, workspace, parent, reason)
		return kerrors.NewForbidden(tenancyv1beta1.Resource("workspaces"), workspace, fmt.Errorf("%q workspace access not permitted", clusterName))
	}

	return nil
}

// List retrieves a list of Workspaces that match label.
func (s *REST) List(ctx context.Context, options *metainternal.ListOptions) (runtime.Object, error) {
	printContextInternals(ctx, false)
	userInfo, ok := apirequest.UserFrom(ctx)
	if !ok {
		return nil, kerrors.NewForbidden(workapiv1.Resource("manifestworks"), "", fmt.Errorf("unable to list manifestworks without a user on the context"))
	}

	value := ctx.Value(ocmworkspace.WorkspaceNameKey)
	workspace := value.(logicalcluster.Name)
	if err := s.authorizeWorkspaceForUser(ctx, workspace, userInfo, "access"); err != nil {
		return nil, err
	}

	manifestworkList := &workapiv1.ManifestWorkList{}

	value = ctx.Value(ocmworkspace.ManagedClusterNameKey)
	managedClusterName := value.(string)
	value = ctx.Value(ocmworkspace.NamespaceKey)
	namespace := value.(string)
	if managedClusterName != namespace {
		return manifestworkList, nil
	}

	labelSelector, fieldSelector := InternalListOptionsToSelectors(options)

	// only select manifestworks from the given cluster namespace
	nsFiledSelector := fields.OneTermEqualSelector("metadata.namespace", managedClusterName)
	if fieldSelector.Empty() {
		fieldSelector = nsFiledSelector
	} else {
		fieldSelector = fields.AndSelectors(fieldSelector, nsFiledSelector)
	}

	for _, workspace := range s.getManifestWorkWorkspaces() {
		matched, err := workspace.List(userInfo, labelSelector, fieldSelector)
		if err != nil {
			return nil, err
		}
		for _, work := range matched.Items {
			manifestworkList.Items = append(manifestworkList.Items, projection.ProjectManifestWork(work))
		}
	}

	sort.Slice(manifestworkList.Items, func(i, j int) bool {
		return manifestworkList.Items[i].Name < manifestworkList.Items[j].Name
	})
	return manifestworkList, nil
}

var _ = rest.Getter(&REST{})

// Get retrieves a Workspace by name
func (s *REST) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	fmt.Printf("++++>REST.Get(): name=%s\n", name)

	userInfo, ok := apirequest.UserFrom(ctx)
	if !ok {
		return nil, kerrors.NewForbidden(workapiv1.Resource("manifestworks"), "", fmt.Errorf("unable to get manifestwork without a user on the context"))
	}

	value := ctx.Value(ocmworkspace.ManagedClusterNameKey)
	managedClusterName := value.(string)
	value = ctx.Value(ocmworkspace.WorkspaceNameKey)
	workspace := value.(logicalcluster.Name)
	if err := s.authorizeWorkspaceForUser(ctx, workspace, userInfo, "access"); err != nil {
		return nil, err
	}

	// only select manifestworks from the given cluster namespace
	filedSelector := fields.OneTermEqualSelector("metadata.namespace", managedClusterName)
	for clusterName, workspace := range s.getManifestWorkWorkspaces() {
		fmt.Printf("++++>REST.Get(): checking workspace %q\n", clusterName.String())
		projectedClusterName := strings.ReplaceAll(clusterName.String(), ":", "-")
		prefix := fmt.Sprintf("%s-", projectedClusterName)
		if !strings.HasPrefix(name, prefix) {
			fmt.Printf("++++>REST.Get(): name %q has no prefix %q, skipped\n", name, prefix)
			continue
		}

		matched, err := workspace.List(userInfo, labels.Everything(), fields.AndSelectors(
			filedSelector,
			fields.OneTermEqualSelector("metadata.name", strings.TrimPrefix(name, prefix))))
		if err != nil {
			return nil, err
		}

		if len(matched.Items) > 0 {
			projected := projection.ProjectManifestWork(matched.Items[0])
			return &projected, nil
		}
	}

	return nil, kerrors.NewNotFound(workapiv1.Resource("manifestworks"), name)
}

/*
func (s *REST) Watch(ctx context.Context, options *metainternal.ListOptions) (watch.Interface, error) {
	userInfo, exists := apirequest.UserFrom(ctx)
	if !exists {
		return nil, fmt.Errorf("no user")
	}

	orgClusterName := ctx.Value(WorkspacesOrgKey).(logicalcluster.Name)
	if err := s.authorizeOrgForUser(ctx, orgClusterName, userInfo, "access"); err != nil {
		return nil, err
	}
	clusterWorkspaces := s.getFilteredClusterWorkspaces(orgClusterName)

	includeAllExistingProjects := (options != nil) && options.ResourceVersion == "0"

	m := workspaceutil.MatchWorkspace(InternalListOptionsToSelectors(options))
	watcher := workspaceauth.NewUserWorkspaceWatcher(userInfo, orgClusterName, s.clusterWorkspaceCache, clusterWorkspaces, includeAllExistingProjects, m)
	clusterWorkspaces.AddWatcher(watcher)

	go watcher.Watch()
	return watcher, nil
}

type RoleType string

const (
	OwnerRoleType RoleType = "owner"
)

var roleRules = map[RoleType][]rbacv1.PolicyRule{
	OwnerRoleType: {
		{
			Verbs:     []string{"get", "delete"},
			Resources: []string{"clusterworkspaces/workspace"},
		},
		{
			Resources: []string{"clusterworkspaces/content"},
			Verbs:     []string{"admin", "access"},
		},
	},
}

func createClusterRole(name, workspaceName string, roleType RoleType) *rbacv1.ClusterRole {
	var rules []rbacv1.PolicyRule
	for _, rule := range roleRules[roleType] {
		rule.APIGroups = []string{tenancyv1beta1.SchemeGroupVersion.Group}
		rule.ResourceNames = []string{workspaceName}
		rules = append(rules, rule)
	}
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{},
		},
		Rules: rules,
	}
}

func getRoleBindingName(roleType RoleType, workspacePrettyName string, user kuser.Info) string {
	return string(roleType) + "-workspace-" + workspacePrettyName + "-" + user.GetName()
}
*/

func InternalListOptionsToSelectors(options *metainternal.ListOptions) (labels.Selector, fields.Selector) {
	label := labels.Everything()
	if options != nil && options.LabelSelector != nil {
		label = options.LabelSelector
	}
	field := fields.Everything()
	if options != nil && options.FieldSelector != nil {
		field = options.FieldSelector
	}
	return label, field
}

var decisions = map[authorizer.Decision]string{
	authorizer.DecisionAllow:     "allowed",
	authorizer.DecisionDeny:      "denied",
	authorizer.DecisionNoOpinion: "denied",
}

/*
var _ = rest.Creater(&REST{})

// Create creates a new workspace
// The workspace is created in the underlying KCP server, with an internal name
// since the name ( == pretty name ) requested by the user might already exist at the organization level.
// Internal names would be <pretty name>--<suffix>.
//
// However, when the user manages his workspaces through the personal scope, the pretty names will always be used.
//
// Personal pretty names and the related internal names are stored on the ClusterRoleBinding that links the
// ClusterWorkspace-related ClusterRole with the user Subject.
//
// Typical actions done against the underlying KCP instance when
//
//   kubectl create workspace my-app
//
// is issued by User-A against the virtual workspace at the personal scope:
//
//   1. create ClusterRoleBinding owner-workspace-my-app-user-A
//
// If this fails, then my-app already exists for the user A => conflict error.
//
//   2. create ClusterRoleBinding owner-workspace-my-app-user-A
//      create ClusterRole owner-workspace-my-app-user-A
//
//   3. create ClusterWorkspace my-app
//
// If this conflicts, create my-app--1, then my-app--2, …
//
//   4. update RoleBinding user-A-my-app to point to my-app-2 instead of my-app.
//
//   5. update ClusterRole owner-workspace-my-app-user-A to point to the internal workspace name
//      update the internalName and pretty annotation on cluster roles and cluster role bindings.
//
func (s *REST) Create(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	var zero int64
	userInfo, ok := apirequest.UserFrom(ctx)
	if !ok {
		return nil, kerrors.NewForbidden(tenancyv1beta1.Resource("workspaces"), "", fmt.Errorf("unable to create a workspace without a user on the context"))
	}

	orgClusterName := ctx.Value(WorkspacesOrgKey).(logicalcluster.Name)
	if err := s.authorizeOrgForUser(ctx, orgClusterName, userInfo, "member"); err != nil {
		return nil, err
	}

	workspace, isWorkspace := obj.(*tenancyv1beta1.Workspace)
	if !isWorkspace {
		return nil, kerrors.NewInvalid(tenancyv1beta1.SchemeGroupVersion.WithKind("Workspace").GroupKind(), obj.GetObjectKind().GroupVersionKind().String(), []*field.Error{})
	}

	// check whether the user is allowed to use the cluster workspace type
	authz, err := s.delegatedAuthz(orgClusterName, s.kubeClusterClient)
	if err != nil {
		klog.Errorf("failed to get delegated authorizer for logical cluster %s", userInfo.GetName(), orgClusterName)
		return nil, kerrors.NewForbidden(tenancyv1beta1.Resource("workspaces"), "", fmt.Errorf("use of the cluster workspace type %q in workspace %q is not allowed", workspace.Spec.Type, orgClusterName))
	}
	typeName := strings.ToLower(workspace.Spec.Type)
	if len(typeName) == 0 {
		typeName = "universal"
	}
	typeUseAttr := authorizer.AttributesRecord{
		User:            userInfo,
		Verb:            "use",
		APIGroup:        tenancyv1alpha1.SchemeGroupVersion.Group,
		APIVersion:      tenancyv1alpha1.SchemeGroupVersion.Version,
		Resource:        "clusterworkspacetypes",
		Name:            typeName,
		ResourceRequest: true,
	}
	if decision, reason, err := authz.Authorize(ctx, typeUseAttr); err != nil {
		klog.Errorf("failed to authorize user %q to %q clusterworkspacetypes name %q in %s", userInfo.GetName(), "use", typeName, orgClusterName)
		return nil, kerrors.NewForbidden(tenancyv1beta1.Resource("workspaces"), workspace.Name, fmt.Errorf("use of the cluster workspace type %q in workspace %q is not allowed", workspace.Spec.Type, orgClusterName))
	} else if decision != authorizer.DecisionAllow {
		klog.Errorf("user %q lacks (%s) clusterworkspacetypes %q permission for %q in %s: %s", userInfo.GetName(), decisions[decision], "use", typeName, orgClusterName, reason)
		return nil, kerrors.NewForbidden(tenancyv1beta1.Resource("workspaces"), workspace.Name, fmt.Errorf("use of the cluster workspace type %q in workspace %q is not allowed", workspace.Spec.Type, orgClusterName))
	}

	ownerRoleBindingName := getRoleBindingName(OwnerRoleType, workspace.Name, userInfo)

	// First create the ClusterRoleBinding that will link the workspace cluster role with the user Subject
	// This is created with a name unique inside the user personal scope (pretty name + userName),
	// So this automatically check for pretty name uniqueness in the user personal scope.
	clusterRoleBinding := rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   ownerRoleBindingName,
			Labels: map[string]string{},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			APIGroup: "rbac.authorization.k8s.io",
			Name:     ownerRoleBindingName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "User",
				Name:      userInfo.GetName(),
				Namespace: "",
			},
		},
	}
	if _, err := s.kubeClusterClient.Cluster(orgClusterName).RbacV1().ClusterRoleBindings().Create(ctx, &clusterRoleBinding, metav1.CreateOptions{}); err != nil {
		if kerrors.IsAlreadyExists(err) {
			return nil, kerrors.NewAlreadyExists(tenancyv1beta1.Resource("workspaces"), workspace.Name)
		}
		return nil, kerrors.NewForbidden(tenancyv1beta1.Resource("workspaces"), workspace.Name, err)
	}

	// Then create the owner role related to the given workspace.
	// Note that ResourceNames contains the workspace pretty name for now.
	// It will be updated later on when the internal name of the workspace is known.
	ownerClusterRole := createClusterRole(ownerRoleBindingName, workspace.Name, OwnerRoleType)
	if _, err := s.kubeClusterClient.Cluster(orgClusterName).RbacV1().ClusterRoles().Create(ctx, ownerClusterRole, metav1.CreateOptions{}); err != nil && !kerrors.IsAlreadyExists(err) {
		return nil, kerrors.NewForbidden(tenancyv1beta1.Resource("workspaces"), workspace.Name, err)
	}

	// Then try to create the workspace object itself, first with the pretty name,
	// retrying with increasing suffixes until a workspace with the same name
	// doesn't already exist.
	// The suffixed name based on the pretty name will be the internal name
	clusterWorkspace := &tenancyv1alpha1.ClusterWorkspace{
		ObjectMeta: workspace.ObjectMeta,
		Spec: tenancyv1alpha1.ClusterWorkspaceSpec{
			Type: workspace.Spec.Type,
		},
	}
	createdClusterWorkspace, err := s.kcpClusterClient.Cluster(orgClusterName).TenancyV1alpha1().ClusterWorkspaces().Create(ctx, clusterWorkspace, metav1.CreateOptions{})
	if err != nil && kerrors.IsAlreadyExists(err) {
		clusterWorkspace.Name = ""
		clusterWorkspace.GenerateName = workspace.Name + "-"
		createdClusterWorkspace, err = s.kcpClusterClient.Cluster(orgClusterName).TenancyV1alpha1().ClusterWorkspaces().Create(ctx, clusterWorkspace, metav1.CreateOptions{})
	}
	if err != nil {
		_ = s.kubeClusterClient.Cluster(orgClusterName).RbacV1().ClusterRoles().Delete(ctx, ownerClusterRole.Name, metav1.DeleteOptions{GracePeriodSeconds: &zero})
		_ = s.kubeClusterClient.Cluster(orgClusterName).RbacV1().ClusterRoleBindings().Delete(ctx, clusterRoleBinding.Name, metav1.DeleteOptions{GracePeriodSeconds: &zero})
		return nil, err
	}

	// Update the cluster roles with the new workspace internal name, and also
	// add the internal name as a label, to allow searching with it later on.
	for i := range ownerClusterRole.Rules {
		ownerClusterRole.Rules[i].ResourceNames = []string{createdClusterWorkspace.Name}
	}
	ownerClusterRole.Labels[InternalNameLabel] = createdClusterWorkspace.Name
	if _, err := s.kubeClusterClient.Cluster(orgClusterName).RbacV1().ClusterRoles().Update(ctx, ownerClusterRole, metav1.UpdateOptions{}); err != nil {
		_ = s.kubeClusterClient.Cluster(orgClusterName).RbacV1().ClusterRoles().Delete(ctx, ownerClusterRole.Name, metav1.DeleteOptions{GracePeriodSeconds: &zero})
		_, _, _ = s.Delete(ctx, createdClusterWorkspace.Name, nil, &metav1.DeleteOptions{GracePeriodSeconds: &zero})
		if kerrors.IsConflict(err) {
			return nil, kerrors.NewConflict(tenancyv1beta1.Resource("workspaces"), workspace.Name, err)
		}
		return nil, kerrors.NewForbidden(tenancyv1beta1.Resource("workspaces"), workspace.Name, err)
	}

	// Update the cluster role bindings with the new workspace internal and pretty names,
	// to allow searching with them later on.
	clusterRoleBinding.Labels[InternalNameLabel] = createdClusterWorkspace.Name
	clusterRoleBinding.Labels[PrettyNameLabel] = workspace.Name
	if _, err := s.kubeClusterClient.Cluster(orgClusterName).RbacV1().ClusterRoleBindings().Update(ctx, &clusterRoleBinding, metav1.UpdateOptions{}); err != nil {
		var zero int64
		_ = s.kubeClusterClient.Cluster(orgClusterName).RbacV1().ClusterRoleBindings().Delete(ctx, clusterRoleBinding.Name, metav1.DeleteOptions{GracePeriodSeconds: &zero})
		_, _, _ = s.Delete(ctx, createdClusterWorkspace.Name, nil, &metav1.DeleteOptions{GracePeriodSeconds: &zero})
		if kerrors.IsConflict(err) {
			return nil, kerrors.NewConflict(tenancyv1beta1.Resource("workspaces"), workspace.Name, err)
		}
		return nil, kerrors.NewForbidden(tenancyv1beta1.Resource("workspaces"), workspace.Name, err)
	}

	var createdWorkspace tenancyv1beta1.Workspace
	projection.ProjectClusterWorkspaceToWorkspace(createdClusterWorkspace, &createdWorkspace)

	// The workspace has been created with the internal name in KCP,
	// but will be returned to the user (in personal scope) with the pretty name.
	createdWorkspace.Name = workspace.Name
	return &createdWorkspace, nil
}

var _ = rest.GracefulDeleter(&REST{})

func (s *REST) Delete(ctx context.Context, name string, deleteValidation rest.ValidateObjectFunc, options *metav1.DeleteOptions) (runtime.Object, bool, error) {
	userInfo, ok := apirequest.UserFrom(ctx)
	if !ok {
		return nil, false, kerrors.NewForbidden(tenancyv1beta1.Resource("workspaces"), name, fmt.Errorf("unable to delete a workspace without a user on the context"))
	}

	orgClusterName := ctx.Value(WorkspacesOrgKey).(logicalcluster.Name)
	if err := s.authorizeOrgForUser(ctx, orgClusterName, userInfo, "access"); err != nil {
		return nil, false, err
	}

	internalName := name

	// check for delete permission on the ClusterWorkspace workspace subresource
	authz, err := s.delegatedAuthz(orgClusterName, s.kubeClusterClient)
	if err != nil {
		klog.Errorf("failed to get delegated authorizer for logical cluster %s", userInfo, orgClusterName)
		return nil, false, kerrors.NewForbidden(tenancyv1beta1.Resource("workspaces"), name, fmt.Errorf("deletion in workspace %q is not allowed", orgClusterName))
	}
	deleteWorkspaceAttr := authorizer.AttributesRecord{
		User:            userInfo,
		Verb:            "delete",
		APIGroup:        tenancyv1alpha1.SchemeGroupVersion.Group,
		APIVersion:      tenancyv1alpha1.SchemeGroupVersion.Version,
		Resource:        "clusterworkspaces",
		Subresource:     "workspace",
		Name:            internalName,
		ResourceRequest: true,
	}
	if decision, _, err := authz.Authorize(ctx, deleteWorkspaceAttr); err != nil {
		klog.Errorf("failed to authorize user %q to %q clusterworkspaces/workspace name %q in %s", userInfo.GetName(), "delete", internalName, orgClusterName)
		return nil, false, kerrors.NewForbidden(tenancyv1beta1.Resource("workspaces"), "", fmt.Errorf("deletion in workspace %q is not allowed", orgClusterName))
	} else if decision != authorizer.DecisionAllow {
		// check for admin verb on the content
		contentAdminAttr := authorizer.AttributesRecord{
			User:            userInfo,
			Verb:            "admin",
			APIGroup:        tenancyv1alpha1.SchemeGroupVersion.Group,
			APIVersion:      tenancyv1alpha1.SchemeGroupVersion.Version,
			Resource:        "clusterworkspaces",
			Subresource:     "content",
			Name:            internalName,
			ResourceRequest: true,
		}
		if decision, reason, err := authz.Authorize(ctx, contentAdminAttr); err != nil {
			klog.Errorf("failed to authorize user %q to %q clusterworkspaces/content name %q in %s", userInfo.GetName(), "admin", internalName, orgClusterName)
			return nil, false, kerrors.NewForbidden(tenancyv1beta1.Resource("workspaces"), "", fmt.Errorf("deletion in workspace %q is not allowed", orgClusterName))
		} else if decision != authorizer.DecisionAllow {
			klog.Errorf("user %q lacks (%s) clusterworkspaces/content %q permission and clusterworkspaces/workspace %s permission for %q in %s: %s", userInfo.GetName(), decisions[decision], "admin", "delete", internalName, orgClusterName, reason)
			return nil, false, kerrors.NewForbidden(tenancyv1beta1.Resource("workspaces"), internalName, fmt.Errorf("deletion in workspace %q is not allowed", orgClusterName))
		}
	}

	errorToReturn := s.kcpClusterClient.Cluster(orgClusterName).TenancyV1alpha1().ClusterWorkspaces().Delete(ctx, internalName, *options)
	if err != nil && !kerrors.IsNotFound(errorToReturn) {
		return nil, false, err
	}
	internalNameLabelSelector := fmt.Sprintf("%s=%s", InternalNameLabel, internalName)
	if err := s.kubeClusterClient.Cluster(orgClusterName).RbacV1().ClusterRoles().DeleteCollection(ctx, *options, metav1.ListOptions{
		LabelSelector: internalNameLabelSelector,
	}); err != nil {
		klog.Error(err)
	}
	if err := s.kubeClusterClient.Cluster(orgClusterName).RbacV1().ClusterRoleBindings().DeleteCollection(ctx, *options, metav1.ListOptions{
		LabelSelector: internalNameLabelSelector,
	}); err != nil {
		klog.Error(err)
	}

	return nil, false, errorToReturn
}



func HasManagedCluster(cluterName string) bool {
	return true
}
*/

func printContextInternals(ctx interface{}, inner bool) {
	contextValues := reflect.ValueOf(ctx).Elem()
	contextKeys := reflect.TypeOf(ctx).Elem()

	if !inner {
		fmt.Printf("\nFields for %s.%s\n", contextKeys.PkgPath(), contextKeys.Name())
	}

	if contextKeys.Kind() == reflect.Struct {
		for i := 0; i < contextValues.NumField(); i++ {
			reflectValue := contextValues.Field(i)
			reflectValue = reflect.NewAt(reflectValue.Type(), unsafe.Pointer(reflectValue.UnsafeAddr())).Elem()

			reflectField := contextKeys.Field(i)

			if reflectField.Name == "Context" {
				printContextInternals(reflectValue.Interface(), true)
			} else {
				fmt.Printf("field name: %+v\n", reflectField.Name)
				fmt.Printf("value: %+v\n", reflectValue.Interface())
			}
		}
	} else {
		fmt.Printf("context is empty (int)\n")
	}
}
