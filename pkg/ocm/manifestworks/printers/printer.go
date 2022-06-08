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

package printers

import (
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kprinters "k8s.io/kubernetes/pkg/printers"

	workapiv1 "open-cluster-management.io/api/work/v1"
)

func AddManifestWorkPrintHandlers(h kprinters.PrintHandler) {
	manifestworkColumnDefinitions := []metav1.TableColumnDefinition{
		{
			Name:        "Namespace",
			Type:        "string",
			Format:      "namespace",
			Description: metav1.ObjectMeta{}.SwaggerDoc()["namespace"],
			Priority:    0,
		},
		{
			Name:        "Name",
			Type:        "string",
			Format:      "name",
			Description: metav1.ObjectMeta{}.SwaggerDoc()["name"],
			Priority:    0,
		},
	}

	if err := h.TableHandler(manifestworkColumnDefinitions, printManifestWorkList); err != nil {
		panic(err)
	}
	if err := h.TableHandler(manifestworkColumnDefinitions, printManifestWork); err != nil {
		panic(err)
	}
}

func printManifestWork(manifestwork *workapiv1.ManifestWork, options kprinters.GenerateOptions) ([]metav1.TableRow, error) {
	row := metav1.TableRow{
		Object: runtime.RawExtension{Object: manifestwork},
	}

	row.Cells = append(row.Cells, manifestwork.Namespace, manifestwork.Name)

	return []metav1.TableRow{row}, nil
}

func printManifestWorkList(list *workapiv1.ManifestWorkList, options kprinters.GenerateOptions) ([]metav1.TableRow, error) {
	sort.Sort(SortableManifestWorks(list.Items))
	rows := make([]metav1.TableRow, 0, len(list.Items))
	for i := range list.Items {
		r, err := printManifestWork(&list.Items[i], options)
		if err != nil {
			return nil, err
		}
		rows = append(rows, r...)
	}
	return rows, nil
}

// SortableManifestWorks is a list of manifestworks that can be sorted
type SortableManifestWorks []workapiv1.ManifestWork

func (list SortableManifestWorks) Len() int {
	return len(list)
}

func (list SortableManifestWorks) Swap(i, j int) {
	list[i], list[j] = list[j], list[i]
}

func (list SortableManifestWorks) Less(i, j int) bool {
	return list[i].ObjectMeta.Name < list[j].ObjectMeta.Name
}
