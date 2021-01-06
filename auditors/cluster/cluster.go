package cluster

import (
	"github.com/majeinfo/kubesecaudit/audit"
	"github.com/majeinfo/kubesecaudit/internal/k8s"
	"github.com/majeinfo/kubesecaudit/k8stypes"
	"strings"
)

const Name = "cluster"

const (
	DeploymentPodsOnSameNode = "DeploymentPodsOnSameNode"
)

// ClusterArchitectureRules implements Auditable
type ClusterArchitectureRules struct{}

func New() *ClusterArchitectureRules {
	return &ClusterArchitectureRules{}
}

// Check the best practice rules for the whole cluster
func (a *ClusterArchitectureRules) Audit(resources []k8stypes.Resource) ([]*audit.AuditResult, error) {
	var auditResults []*audit.AuditResult

	for _, resource := range resources {
		auditResults = append(auditResults, auditIsReplicaSetHA(resource, resources)...)
	}

	return auditResults, nil
}

// Check if Deployment/ReplicaSet are HA (ex: are the CoreDNS PODs located on the same none or not ?)
func auditIsReplicaSetHA(resource k8stypes.Resource, resources []k8stypes.Resource) []*audit.AuditResult {
	var auditResults []*audit.AuditResult

	// Start from Deployment where replicas > 0
	if !k8stypes.IsDeploymentV1(resource) {
		return auditResults
	}

	depl := resource.(*k8stypes.DeploymentV1)
	if *depl.Spec.Replicas < 2 {
		return auditResults
	}

	// Get the matching ReplicaSet
	depl_meta := depl.GetObjectMeta()
	rss := k8s.FindReplicaSetFromParent(depl_meta.GetName(), depl_meta.GetNamespace(), resources)
	for _, rs := range rss {
		if rs == nil || *rs.Spec.Replicas < 2 {
			continue
		}

		hostList := make(map[string]struct{})
		var podNames []string

		// Get the matching PODs
		rs_meta := rs.GetObjectMeta()
		pods := k8s.FindPodFromParent(rs_meta.GetName(), rs_meta.GetNamespace(), resources)
		for _, pod := range pods {
			hostList[pod.Status.HostIP] = struct{}{}
			podNames = append(podNames, pod.Name)
		}

		if len(hostList) < 2 {
			auditResult := &audit.AuditResult{
				Name:     DeploymentPodsOnSameNode,
				Severity: audit.Warn,
				Message:  "All the Pods are located on the same Node: this is not H-A !",
				Resource: &resource,	// BUG ???? &resources[idx]
				PendingFix: &fixPodAntiAffinityAdded{},
				Metadata: audit.Metadata{
					"PodNames": strings.Join(podNames, ", "),
				},
			}
			auditResults = append(auditResults, auditResult)
		}
	}

	return auditResults
}
