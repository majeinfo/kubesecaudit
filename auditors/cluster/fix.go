package cluster

import (
	"fmt"

	//"github.com/majeinfo/kubesecaudit/k8stypes"
)

type fixPodAntiAffinityAdded struct {
}

func (f *fixPodAntiAffinityAdded) Plan() string {
	return fmt.Sprintf("Add a spec.affinity.podAntiAffinity rule in the Pod specification")
}



