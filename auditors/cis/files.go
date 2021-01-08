package cis

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"

	"github.com/majeinfo/kubesecaudit/audit"
)

// Check the owner and permissions of configuration files
func auditFiles(cis *CISConfig) []*audit.AuditResult {
	var auditResults []*audit.AuditResult

	// Handle config file
	if cis.config.KubadmConf != "" { filesToAudit[conf_kubadmConf].fname = cis.config.KubadmConf }
	if cis.config.ApiserverPod != "" { filesToAudit[conf_apiserverPod].fname = cis.config.ApiserverPod }
	if cis.config.ControllerManagerPod != "" { filesToAudit[conf_controllerManagerPod].fname = cis.config.ControllerManagerPod }
	if cis.config.ControllerManagerConf != "" { filesToAudit[conf_controllerManagerConf].fname = cis.config.ControllerManagerConf }
	if cis.config.KubeSchedulerPod != "" { filesToAudit[conf_kubeSchedulerPod].fname = cis.config.KubeSchedulerPod }
	if cis.config.KubeSchedulerConf != "" { filesToAudit[conf_kubeSchedulerConf].fname = cis.config.KubeSchedulerConf }
	if cis.config.KubeEtcdPod != "" { filesToAudit[conf_kubeEtcdPod].fname = cis.config.KubeEtcdPod }
	if cis.config.KubeletConf != "" { filesToAudit[conf_kubeletConf].fname = cis.config.KubeletConf }
	if cis.config.K8sPkiDir != "" { filesToAudit[conf_k8sPkiDir].fname = cis.config.K8sPkiDir }
	if cis.config.KubeEtcdPod != "" { filesToAudit[conf_kubeEtcdPod].fname = cis.config.KubeEtcdPod }
	if cis.config.KubeletService != "" { filesToAudit[conf_kubeletService].fname = cis.config.KubeletService }

	for _, desc := range filesToAudit {
		res := checkOwnerAndPerms(desc.fname, desc.owner, desc.group, desc.perms)
		auditResults = append(auditResults, res...)
	}

	// TODO: *crt and *key

	return auditResults
}

func checkOwnerAndPerms(fname string, user_spec string, group_spec string, mode int) []*audit.AuditResult {
	var auditResults []*audit.AuditResult

	fileinfo, err := os.Stat(fname)
	if err != nil {
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

		return auditResults
	}

	// Check permissions
	if (fileinfo.Mode().Perm() &^ os.FileMode(mode)) != 0 {
		auditResult := &audit.AuditResult{
			Name:     FilePermsError,
			Severity: audit.Error,
			Message:  "File Permission should not be greater than " + fmt.Sprintf("%o", mode),
			Metadata: audit.Metadata{
				"File": fname,
				"Perms": fmt.Sprintf("%o", fileinfo.Mode().Perm()),
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	// Check owner and group
	stat := fileinfo.Sys().(*syscall.Stat_t)
	uid := stat.Uid
	u := strconv.FormatUint(uint64(uid), 10)
	usr, err := user.LookupId(u)

	if user_spec != u && (user_spec != usr.Username || err != nil) {
		username := u
		if err == nil {
			username = usr.Username
		}
		auditResult := &audit.AuditResult{
			Name:     FileOwnerError,
			Severity: audit.Error,
			Message:  "File Owner should be " + user_spec,
			Metadata: audit.Metadata{
				"File": fname,
				"Owner": username,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	gid := stat.Gid
	g := strconv.FormatUint(uint64(gid), 10)
	group, err := user.LookupGroupId(g)

	if group_spec != g && (group_spec != group.Name || err != nil) {
		groupname := g
		if err == nil {
			groupname = group.Name
		}
		auditResult := &audit.AuditResult{
			Name:     FileGroupOwnerError,
			Severity: audit.Error,
			Message:  "File Group Owner should be " + group_spec,
			Metadata: audit.Metadata{
				"File": fname,
				"GroupOwner": groupname,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	return auditResults
}

