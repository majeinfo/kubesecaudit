package cis

// Implements the CIS Benchmark tests

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"

	"github.com/majeinfo/kubesecaudit/audit"
	"github.com/majeinfo/kubesecaudit/k8stypes"
)

const Name = "cis"

// Possible Audit Messages
const (
	FileError = "FileError"
	FilePermsError = "FilePermsError"
	FileOwnerError = "FileOwnerError"
	FileGroupOwnerError = "FileGroupOwnerError"

	KubeApiServerNotFound = "KubeApiServerNotFound"
	AnonymousAuthEnabled = "AnonymousAuthEnabled"
	BasicAuthFileDefined = "BasicAuthFileDefined"
	TokenAuthFileDefined = "TokenAuthFileDefined"
	AuthModeAlwaysAllowEnabled = "AuthModeAlwaysAllowEnabled"
	AuthModeNodeDisabled = "AuthModeNodeDisabled"
	AuthModeRBACDisabled = "AuthModeRBACDisabled"
	AdmissionControllerEventRateLimitDisabled = "AdmissionControllerEventRateLimitDisabled"
	AdmissionControllerAlwaysPullImagesDisabled = "AdmissionControllerAlwaysPullImagesDisabled"
	AdmissionControllerAlwaysAdmitEnabled = "AdmissionControllerAlwaysAdmitEnabled"
	AdmissionControllerSecurityContextDenyDisabled = "AdmissionControllerSecurityContextDenyDisabled"
	AdmissionControllerServiceAccountDisabled = "AdmissionControllerServiceAccountDisabled"
	AdmissionControllerNamespaceLifecycleDisabled = "AdmissionControllerNamespaceLifecycleDisabled"
	AdmissionControllerPodSecurityPolicyDisabled = "AdmissionControllerPodSecurityPolicyDisabled"
	AdmissionControllerNodeSecurityDisabled = "AdmissionControllerNodeSecurityDisabled"
	KubeletCertificateAuthorityDisabled = "KubeletCertificateAuthorityDisabled"
)

type fileToAudit struct {
	fname string
	owner string
	group string
	perms int
}
var filesToAudit map[string]*fileToAudit

// ClusterArchitectureRules implements Auditable and GlobalAudit
type CISConfig struct{
	config Config
}

const (
	conf_kubadmConf = "kubadmConf"
	conf_apiserverPod = "apiserverPod"
	conf_controllerManagerPod = "controllerManagerPod"
	conf_controllerManagerConf = "controllerManagerConf"
	conf_kubeSchedulerPod = "kubeSchedulerPod"
	conf_kubeSchedulerConf = "kubeSchedulerConf"
	conf_kubeEtcdPod = "kubeEtcdPod"
	conf_kubeletConf = "kubeletConf"
	conf_k8sPkiDir = "k8sPkiDir"
	conf_kubeletService = "kubeletService"

	proc_apiserver = "kube-apiserver"
)

func init() {
	filesToAudit = map[string]*fileToAudit{
		conf_kubadmConf: { "/etc/kubernetes/admin.conf", "root", "root", 0640 },
		conf_apiserverPod: { "/etc/kubernetes/manifests/kube-apiserver.yaml", "root", "root", 0644 },
		conf_controllerManagerPod: { "/etc/kubernetes/manifests/kube-controller-manager.yaml", "root", "root", 0644 },
		conf_controllerManagerConf: { "/etc/kubernetes/controller-manager.conf", "root", "root", 0644 },
		conf_kubeSchedulerPod: { "/etc/kubernetes/manifests/kube-scheduler.yaml", "root", "root", 0644 },
		conf_kubeSchedulerConf: { "/etc/kubernetes/scheduler.conf", "root", "root", 0644 },
		conf_kubeEtcdPod: { "/etc/kubernetes/manifests/kube-etcd.yaml", "root", "root", 0644 },
		conf_kubeletConf: { "/etc/kubernetes/kubelet.conf", "root", "root", 0644 },
		conf_k8sPkiDir: { "/etc/kubernetes/pki", "root", "root", 0755 },
		//{ "/etc/kubernetes/pki/*.crt", "root", "root", 0644 },
		//{ "/etc/kubernetes/pki/*.key", "root", "root", 0600 },
		conf_kubeletService: { "/etc/systemd/system/multi-user.target.wants/kubelet.service", "root", "root", 0644 },
	}
}

func New(config Config) *CISConfig {
	return &CISConfig{
		config: config,
	}
}

// Check the best practice rules for the whole cluster
func (cis *CISConfig) Audit(resources []k8stypes.Resource) ([]*audit.AuditResult, error) {
	var auditResults []*audit.AuditResult

	auditResults = append(auditResults, auditFiles(cis)...)
	processes, err := GetAllProcesses()
	if err != nil {
		return auditResults, err
	}
	auditResults = append(auditResults, auditAPIServer(processes)...)

	return auditResults, nil
}

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

