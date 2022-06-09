package workspace

type ScopeKeyType string

const (
	NamespaceKey          ScopeKeyType = "open-cluster-management.io/Namespace"
	ManagedClusterNameKey ScopeKeyType = "open-cluster-management.io/ManagedClusterName"
	WorkspaceNameKey      ScopeKeyType = "open-cluster-management.io/WorkspaceName"
)
