package cis

// Implements the CIS Benchmark tests

import (
	_ "fmt"
	"github.com/majeinfo/kubesecaudit/audit"
	"github.com/majeinfo/kubesecaudit/k8stypes"
	_ "os"

	//"github.com/majeinfo/kubeaudit/audit"
	//"github.com/majeinfo/kubeaudit/k8stypes"
)

const Name = "cis"

const (
	FileError = "FileError"
	FilePermsError = "FilePermsError"
)

// ClusterArchitectureRules implements Auditable and GlobalAudit
type CISBenchmarkRules struct{}

func New() *CISBenchmarkRules {
	return &CISBenchmarkRules{}
}

// Check the best practice rules for the whole cluster
func (a *CISBenchmarkRules) Audit(resources []k8stypes.Resource) ([]*audit.AuditResult, error) {
	var auditResults []*audit.AuditResult

	//auditResults = append(auditResults, auditFiles()...)

	return auditResults, nil
}

/*
func (a *CISBenchmarkRules) GlobalAudit(resources []k8stypes.Resource) ([]*audit.AuditResult, error) {
	var auditResults []*audit.AuditResult

	auditResults = append(auditResults, auditFiles()...)

	return auditResults, nil
}

// Check the owner and permissions of configuration files
func auditFiles() []*audit.AuditResult {
	var auditResults []*audit.AuditResult

	res := checkOwnerAndPerms("/etc/kubernetes/admin.conf", "root", "root", 0640)
	auditResults = append(auditResults, res...)

	return auditResults
}

func checkOwnerAndPerms(fname string, user string, group string, mode int) []*audit.AuditResult {
	var auditResults []*audit.AuditResult

	if fileinfo, err := os.Stat(fname); err != nil {
		auditResult := &audit.AuditResult{
			Name:     FileError,
			Severity: audit.Warn,
			Message:  "Could not open configuration file",
			Metadata: audit.Metadata{
				"File": fname,
				"Error": err.Error(),
			},
		}
		auditResults = append(auditResults, auditResult)
	} else {
		if (fileinfo.Mode().Perm() & 0640) != 0 {
			auditResult := &audit.AuditResult{
				Name:     FilePermsError,
				Severity: audit.Error,
				Message:  "File Permission should not be greater than 0640",
				Metadata: audit.Metadata{
					"File": fname,
					"Perms": fmt.Sprintf("%o", fileinfo.Mode().Perm()),
				},
			}
			auditResults = append(auditResults, auditResult)
		}
	}

	return auditResults
}
*/
