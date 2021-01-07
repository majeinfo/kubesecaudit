package netpols

import (
	"fmt"

	"github.com/majeinfo/kubesecaudit/audit"
	"github.com/majeinfo/kubesecaudit/internal/override"
	"github.com/majeinfo/kubesecaudit/k8stypes"
)

const Name = "netpols"

const (
	// MissingDefaultDenyIngressAndEgressNetworkPolicy occurs when there is no default deny network policy for
	// ingress and egress traffic
	MissingDefaultDenyIngressAndEgressNetworkPolicy = "MissingDefaultDenyIngressAndEgressNetworkPolicy"
	// MissingDefaultDenyIngressNetworkPolicy occurs when there is no default deny network policy for
	// ingress traffic
	MissingDefaultDenyIngressNetworkPolicy = "MissingDefaultDenyIngressNetworkPolicy"
	// MissingDefaultDenyEgressNetworkPolicy occurs when there is no default deny network policy for
	// egress traffic
	MissingDefaultDenyEgressNetworkPolicy = "MissingDefaultDenyEgressNetworkPolicy"
	// AllowAllIngressNetworkPolicyExists occurs when there is a network policy which allows all ingress traffic
	AllowAllIngressNetworkPolicyExists = "AllowAllIngressNetworkPolicyExists"
	// AllowAllEgressNetworkPolicyExists occurs when there is a network policy which allows all egress traffic
	AllowAllEgressNetworkPolicyExists = "AllowAllEgressNetworkPolicyExists"
)

const (
	IngressOverrideLabel = "allow-non-default-deny-ingress-network-policy"
	EgressOverrideLabel  = "allow-non-default-deny-egress-network-policy"
	Ingress              = "Ingress"
	Egress               = "Egress"
)

// DefaultDenyNetworkPolicies implements Auditable
type DefaultDenyNetworkPolicies struct{}

func New() *DefaultDenyNetworkPolicies {
	return &DefaultDenyNetworkPolicies{}
}

// Audit checks that each namespace resource has a default deny NetworkPolicy for all ingress and egress traffic
func (a *DefaultDenyNetworkPolicies) Audit(resources []k8stypes.Resource) ([]*audit.AuditResult, error) {
	var auditResults []*audit.AuditResult

	for _, resource := range resources {
		if !k8stypes.IsNamespaceV1(resource) {
			return nil, nil
		}

		auditResults = append(auditResults, auditNetworkPoliciesForAllowAll(resource, resources)...)
		auditResults = append(auditResults, auditNetworkPoliciesForDenyAll(resource, resources)...)
	}

	return auditResults, nil
}

func auditNetworkPoliciesForAllowAll(resource k8stypes.Resource, resources []k8stypes.Resource) []*audit.AuditResult {
	var auditResults []*audit.AuditResult

	namespace := getResourceNamespace(resource)
	networkPolicies := getNetworkPolicies(resources, namespace)

	for _, networkPolicy := range networkPolicies {
		auditResults = append(auditResults, auditNetworkPolicy(networkPolicy)...)
	}

	return auditResults
}

func auditNetworkPolicy(networkPolicy *k8stypes.NetworkPolicyV1) []*audit.AuditResult {
	var auditResults []*audit.AuditResult

	if allIngressTrafficAllowed(networkPolicy) {
		auditResult := &audit.AuditResult{
			Name:     AllowAllIngressNetworkPolicyExists,
			Severity: audit.Warn,
			Message:  "Found allow all ingress traffic NetworkPolicy.",
			Metadata: audit.Metadata{
				"PolicyName": networkPolicy.ObjectMeta.Name,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if allEgressTrafficAllowed(networkPolicy) {
		auditResult := &audit.AuditResult{
			Name:     AllowAllEgressNetworkPolicyExists,
			Severity: audit.Warn,
			Message:  "Found allow all egress traffic NetworkPolicy.",
			Metadata: audit.Metadata{
				"PolicyName": networkPolicy.ObjectMeta.Name,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	return auditResults
}

func auditNetworkPoliciesForDenyAll(resource k8stypes.Resource, resources []k8stypes.Resource) []*audit.AuditResult {
	var auditResults []*audit.AuditResult
	namespace := getResourceNamespace(resource)
	networkPolicies := getNetworkPolicies(resources, namespace)
	hasCatchAllNetPol, catchAllNetPol := hasCatchAllNetworkPolicy(networkPolicies)
	hasDefaultDenyIngress := hasDenyAllIngress(networkPolicies)
	hasDefaultDenyEgress := hasDenyAllEgress(networkPolicies)

	if hasCatchAllNetPol {
		if !hasDefaultDenyIngress {
			auditResult := &audit.AuditResult{
				Name:     MissingDefaultDenyIngressNetworkPolicy,
				Severity: audit.Error,
				Message:  fmt.Sprintf("All ingress traffic should be blocked by default for namespace %s.", namespace),
				Metadata: audit.Metadata{
					"Namespace": namespace,
				},
				PendingFix: &fixByAddingPolicyToNetPol{
					networkPolicy: catchAllNetPol,
					policyType:    Ingress,
				},
			}
			auditResult = override.ApplyOverride(auditResult, "", resource, IngressOverrideLabel)
			auditResults = append(auditResults, auditResult)
		}

		if !hasDefaultDenyEgress {
			auditResult := &audit.AuditResult{
				Name:     MissingDefaultDenyEgressNetworkPolicy,
				Severity: audit.Error,
				Message:  fmt.Sprintf("All egress traffic should be blocked by default for namespace %s.", namespace),
				Metadata: audit.Metadata{
					"Namespace": namespace,
				},
				PendingFix: &fixByAddingPolicyToNetPol{
					networkPolicy: catchAllNetPol,
					policyType:    Egress,
				},
			}
			auditResult = override.ApplyOverride(auditResult, "", resource, EgressOverrideLabel)
			auditResults = append(auditResults, auditResult)
		}

		return auditResults
	}

	// We need to manually figure out the overrides because this case involves two override labels
	hasIngressOverride, ingressOverrideReason := override.GetResourceOverrideReason(resource, IngressOverrideLabel)
	hasEgressOverride, egressOverrideReason := override.GetResourceOverrideReason(resource, EgressOverrideLabel)

	if !hasIngressOverride && !hasEgressOverride {
		auditResult := &audit.AuditResult{
			Name:     MissingDefaultDenyIngressAndEgressNetworkPolicy,
			Severity: audit.Error,
			Message:  "Namespace is missing a default deny ingress and egress NetworkPolicy.",
			Metadata: audit.Metadata{
				"Namespace": namespace,
			},
			PendingFix: &fixByAddingNetworkPolicy{
				policyList: []string{"Ingress", "Egress"},
				namespace:  namespace,
			},
		}
		return []*audit.AuditResult{auditResult}
	}

	if hasIngressOverride && hasEgressOverride {
		auditResult := &audit.AuditResult{
			Name:     override.GetOverriddenResultName(MissingDefaultDenyIngressAndEgressNetworkPolicy),
			Severity: audit.Warn,
			Message:  "Namespace is missing a default deny ingress and egress NetworkPolicy.",
			Metadata: audit.Metadata{
				"Namespace":      namespace,
				"OverrideReason": fmt.Sprintf("Ingress: %s, Egress: %s", ingressOverrideReason, egressOverrideReason),
			},
		}
		return []*audit.AuditResult{auditResult}
	}

	// At this point there is exactly one override label for either ingress or egress which means one needs to be
	// fixed and the other is overridden
	auditResult := &audit.AuditResult{
		Name:     MissingDefaultDenyIngressNetworkPolicy,
		Severity: audit.Error,
		Message:  "Namespace is missing a default deny ingress NetworkPolicy.",
		Metadata: audit.Metadata{
			"Namespace": namespace,
		},
		PendingFix: &fixByAddingNetworkPolicy{
			policyList: []string{Ingress},
			namespace:  namespace,
		},
	}
	auditResult = override.ApplyOverride(auditResult, "", resource, IngressOverrideLabel)
	auditResults = append(auditResults, auditResult)

	auditResult = &audit.AuditResult{
		Name:     MissingDefaultDenyEgressNetworkPolicy,
		Severity: audit.Error,
		Message:  "Namespace is missing a default deny egress NetworkPolicy.",
		Metadata: audit.Metadata{
			"Namespace": namespace,
		},
		PendingFix: &fixByAddingNetworkPolicy{
			policyList: []string{Egress},
			namespace:  namespace,
		},
	}
	auditResult = override.ApplyOverride(auditResult, "", resource, EgressOverrideLabel)
	auditResults = append(auditResults, auditResult)

	return auditResults
}

