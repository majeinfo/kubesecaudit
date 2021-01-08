package cis

import (
	"strings"

	"github.com/majeinfo/kubesecaudit/audit"
)

// TODO: should also check the content of the file given by the option --config=file.yml

func auditKubelet(procs []Process) []*audit.AuditResult {
	var auditResults []*audit.AuditResult
	var proc *Process

	if proc = FindProc(procs, proc_kubelet); proc == nil {
		auditResult := &audit.AuditResult{
			Name:     KubeletNotFound,
			Severity: audit.Warn,
			Message:  "Kubelet not found - no audit done",
			Metadata: audit.Metadata{
				"File": proc_kubelet,
			},
		}
		auditResults = append(auditResults, auditResult)
		return auditResults
	}

	options := buildMapFromOptions(proc.options)

	// --anonymous-auth=true by default (YAML file: authentication.anonymous.enabled)
	if value, found := options["anonymous-auth"]; !found || (found && value == "true") {
		auditResult := &audit.AuditResult{
			Name:     KubeletAnonymousAuthEnabled,
			Severity: audit.Error,
			Message:  "Anonymous access is allowed",
			PendingFix: &fixKubeletAnonymousAuthEnabled{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	// (YAML file: tlsCertFile)
	if _, found := options["tls-cert-file"]; !found {
		auditResult := &audit.AuditResult{
			Name:     KubeletTLSCertFileNotSet,
			Severity: audit.Error,
			Message:  "Needs a certificate to be authentified by the api-server",
			PendingFix: &fixKubeletTLSCertFileNotSet{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	// (YAML file: tlsPrivateKeyFile)
	if _, found := options["tls-private-key-file"]; !found {
		auditResult := &audit.AuditResult{
			Name:     KubeletTLSPrivateKeyFileNotSet,
			Severity: audit.Error,
			Message:  "Needs a private key to be authentified by the api-server",
			PendingFix: &fixKubeletTLSPrivateKeyFileNotSet{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	// TODO: rotateCertificates must be true if certificate is given by the api-server

	// (YAML file: authorization.mode)
	if value, found := options["authorization-mode"]; found && strings.Index(value, "AlwaysAllow") != -1 {
		auditResult := &audit.AuditResult{
			Name:     KubeletAlwaysAllowEnabled,
			Severity: audit.Error,
			Message:  "Anonymous access is allowed",
			PendingFix: &fixKubeletAlwaysAllowEnabled{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	// (YAML file: readOnlyPort must be 0)
	// (YAML file: protectKernelDefaults: default true)
	// (YAML file: makeIPTablesUtilChains: default true)

	return auditResults
}

