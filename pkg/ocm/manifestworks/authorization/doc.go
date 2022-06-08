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

// Package authorization provides mechanisms for enforcing authorization to Workspace resources in KCP
// This package is largely inspired from openshift/openshift-apiserver/pkg/project/auth
// https://github.com/openshift/openshift-apiserver/blob/9271466bfd02a9eb02fb5a43c8b9ff1ced76aca9/pkg/project/auth
package authorization
