package cis

import "github.com/majeinfo/kubesecaudit/audit"

// TODO: options can also be defined using environment variables (ETCD_CA_FILE, ETCD_CERT_FILE...)

func auditEtcd(procs []Process) []*audit.AuditResult {
	var auditResults []*audit.AuditResult
	var proc *Process

	if proc = FindProc(procs, proc_etcd); proc == nil {
		auditResult := &audit.AuditResult{
			Name:     EtcdNotFound,
			Severity: audit.Warn,
			Message:  "etcd not found - no audit done",
			Metadata: audit.Metadata{
				"File": proc_etcd,
			},
		}
		auditResults = append(auditResults, auditResult)
		return auditResults
	}

	options := buildMapFromOptions(proc.options)

	if _, found := options["cert-file"]; !found {
		auditResult := &audit.AuditResult{
			Name:     EtcdOptCertFileNotSet,
			Severity: audit.Error,
			Message:  "Etcd does not use any certificate ?",
			PendingFix: &fixEtcdOptCertFileNotSet{},
			Metadata: audit.Metadata{
				"File": proc_etcd,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if _, found := options["key-file"]; !found {
		auditResult := &audit.AuditResult{
			Name:     EtcdOptKeyFileNotSet,
			Severity: audit.Error,
			Message:  "Etcd does not use any private key ?",
			PendingFix: &fixEtcdOptKeyFileNotSet{},
			Metadata: audit.Metadata{
				"File": proc_etcd,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if _, found := options["peer-cert-file"]; !found {
		auditResult := &audit.AuditResult{
			Name:     EtcdOptPeerCertFileNotSet,
			Severity: audit.Error,
			Message:  "Etcd does not use any certificate for intra-member communication ?",
			PendingFix: &fixEtcdOptPeerCertFileNotSet{},
			Metadata: audit.Metadata{
				"File": proc_etcd,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if _, found := options["key-file"]; !found {
		auditResult := &audit.AuditResult{
			Name:     EtcdOptPeerKeyFileNotSet,
			Severity: audit.Error,
			Message:  "Etcd does not use any private key for intra-member communication ?",
			PendingFix: &fixEtcdOptPeerKeyFileNotSet{},
			Metadata: audit.Metadata{
				"File": proc_etcd,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if value, found := options["auto-tls"]; found && value == "true" {
		auditResult := &audit.AuditResult{
			Name:     EtcdOptAutoTLSSet,
			Severity: audit.Error,
			Message:  "Etcd should not allow client to use self-signed certificates",
			PendingFix: &fixEtcdOptAutoTLSSet{},
			Metadata: audit.Metadata{
				"File": proc_etcd,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if value, found := options["client-cert-auth"]; !found || value == "false" {
		auditResult := &audit.AuditResult{
			Name:     EtcdOptClientCertAuthNotSSet,
			Severity: audit.Error,
			Message:  "Etcd should enforce the clients to use a valid certificate",
			PendingFix: &fixEtcdOptClientCertAuthNotSSet{},
			Metadata: audit.Metadata{
				"File": proc_etcd,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if value, found := options["peer-client-cert-auth"]; !found || value == "false" {
		auditResult := &audit.AuditResult{
			Name:     EtcdOptPeerClientCertAuthNotSSet,
			Severity: audit.Error,
			Message:  "Etcd should enforce the members to use a valid certificate to exchange data",
			PendingFix: &fixEtcdOptPeerClientCertAuthNotSSet{},
			Metadata: audit.Metadata{
				"File": proc_etcd,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if value, found := options["peer-auto-tls"]; found && value == "true" {
		auditResult := &audit.AuditResult{
			Name:     EtcdOptPeerAutoTLSSet,
			Severity: audit.Error,
			Message:  "Etcd should not allow members to use self-signed certificates",
			PendingFix: &fixEtcdOptPeerAutoTLSSet{},
			Metadata: audit.Metadata{
				"File": proc_etcd,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if _, found := options["peer-trusted-ca-file"]; !found {
		auditResult := &audit.AuditResult{
			Name:     EtcdOptPeerTrustedCAFileNotSet,
			Severity: audit.Error,
			Message:  "Etcd should define the peer trusted CA for peer communication",
			PendingFix: &fixEtcdOptPeerTrustedCAFileNotSet{},
			Metadata: audit.Metadata{
				"File": proc_etcd,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if _, found := options["trusted-ca-file"]; !found {
		auditResult := &audit.AuditResult{
			Name:     EtcdOptTrustedCAFileNotSet,
			Severity: audit.Error,
			Message:  "Etcd should define the trusted CA for clients communication",
			PendingFix: &fixEtcdOptTrustedCAFileNotSet{},
			Metadata: audit.Metadata{
				"File": proc_etcd,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	// TODO: the CA used for etcd should be different from the one used for K8s components communication
	//       because etcd does not check the Common Names

	return auditResults
}
