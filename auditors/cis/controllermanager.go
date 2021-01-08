package cis

import "github.com/majeinfo/kubesecaudit/audit"

func auditControllerManager(procs []Process) []*audit.AuditResult {
	var auditResults []*audit.AuditResult
	var proc *Process

	if proc = FindProc(procs, proc_controller_manager); proc == nil {
		auditResult := &audit.AuditResult{
			Name:     KubeControllerManagerNotFound,
			Severity: audit.Warn,
			Message:  "Controller-manager not found - no audit done",
			Metadata: audit.Metadata{
				"File": proc_controller_manager,
			},
		}
		auditResults = append(auditResults, auditResult)
		return auditResults
	}

	options := buildMapFromOptions(proc.options)

	if value, found := options["profiling"]; !found || value == "true" {
		auditResult := &audit.AuditResult{
			Name:     CMProfilingEnabled,
			Severity: audit.Error,
			Message:  "Profiling is enabled: it may slow down the Cluster and produce information leaks",
			PendingFix: &fixCMProfilingEnabled{},
			Metadata: audit.Metadata{
				"File": proc_controller_manager,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if value, found := options["user-service-account-credentials"]; !found || value == "false" {
		auditResult := &audit.AuditResult{
			Name:     UserServiceAccountCredentialsNotSet,
			Severity: audit.Error,
			Message:  "The option --user-service-account-credentials should be set to associate a unique ServiceAccount for each Controller. This improves the granularity of RBAC Policies",
			PendingFix: &fixUserServiceAccountCredentialsNotSet{},
			Metadata: audit.Metadata{
				"File": proc_controller_manager,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if _, found := options["service-account-private-key-file"]; !found {
		auditResult := &audit.AuditResult{
			Name:     ServiceAccountPrivateKeyFileNotSet,
			Severity: audit.Error,
			Message:  "The option --service-account-private-key-file should be set to allow ServiceAccount Tokens rotation",
			PendingFix: &fixServiceAccountPrivateKeyFileNotSet{},
			Metadata: audit.Metadata{
				"File": proc_controller_manager,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if _, found := options["root-ca-file"]; !found {
		auditResult := &audit.AuditResult{
			Name:     RootCAFileNotSet,
			Severity: audit.Error,
			Message:  "The option --root-ca-file should be set to inject in the POD the certificate they can use to contact the api-server, avoiding Mitm attack",
			PendingFix: &fixRootCAFileNotSet{},
			Metadata: audit.Metadata{
				"File": proc_controller_manager,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if value, found := options["bind-address"]; !found || (found && value != "127.0.0.1"){
		auditResult := &audit.AuditResult{
			Name:     CMBindAddressNotLocal,
			Severity: audit.Error,
			Message:  "The option --bind-address should be used to restrict the access to the controller-manager through the local IP address",
			PendingFix: &fixCMBindAddressNotLocal{},
			Metadata: audit.Metadata{
				"File": proc_controller_manager,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	return auditResults
}
