package cis

import "github.com/majeinfo/kubesecaudit/audit"

func auditScheduler(procs []Process) []*audit.AuditResult {
	var auditResults []*audit.AuditResult
	var proc *Process

	if proc = FindProc(procs, proc_scheduler); proc == nil {
		auditResult := &audit.AuditResult{
			Name:     KubeSchedulerNotFound,
			Severity: audit.Warn,
			Message:  "Controller-manager not found - no audit done",
			Metadata: audit.Metadata{
				"File": proc_scheduler,
			},
		}
		auditResults = append(auditResults, auditResult)
		return auditResults
	}

	options := buildMapFromOptions(proc.options)

	if value, found := options["profiling"]; !found || value == "true" {
		auditResult := &audit.AuditResult{
			Name:     SchedulerProfilingEnabled,
			Severity: audit.Error,
			Message:  "Profiling is enabled: it may slow down the Cluster and produce information leaks",
			PendingFix: &fixSchedulerProfilingEnabled{},
			Metadata: audit.Metadata{
				"File": proc_scheduler,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if value, found := options["bind-address"]; !found || (found && value != "127.0.0.1"){
		auditResult := &audit.AuditResult{
			Name:     SchedulerBindAddressNotLocal,
			Severity: audit.Error,
			Message:  "The option --bind-address should be used to restrict the access to the scheduler through the local IP address",
			PendingFix: &fixSchedulerBindAddressNotLocal{},
			Metadata: audit.Metadata{
				"File": proc_scheduler,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	return auditResults
}
