package cis

import (
	"errors"
	"fmt"
	"github.com/majeinfo/kubesecaudit/audit"
	"github.com/smallfish/simpleyaml"
	"os"
)

// Check the content of the file given by the option --config=file.yml and the command line options.
// Command line options take precendence over the config file.

func auditKubelet(procs []Process) []*audit.AuditResult {
	var auditResults []*audit.AuditResult
	var proc *Process
	var config_yaml *simpleyaml.Yaml
	var err, is_conf error
	var opt_conf, value string

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

	// Is there a config file ?
	if value, found := options["config"]; found {
		config_yaml, err = readYamlFile(value)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not process kubelet config file %s (%s)", value, err.Error())
		}
	}

	// --anonymous-auth=true by default (YAML file: authentication.anonymous.enabled)
	if config_yaml != nil {
		opt_conf, is_conf = config_yaml.Get("authentication").Get("anonymous").Get("enabled").String()
		value = computeOptionValue("true", opt_conf, is_conf, options, "anonymous-auth")
	} else {
		value = computeOptionValue("true", "", errors.New(""), options, "anonymous-auth")
	}
	if value == "true" {
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
	if config_yaml != nil {
		opt_conf, is_conf = config_yaml.Get("tlsCertFile").String()
		value = computeOptionValue("", opt_conf, is_conf, options, "tls-cert-file")
	} else {
		value = computeOptionValue("", "", errors.New(""), options, "tls-cert-file")
	}
	if value == "" {
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
	if config_yaml != nil {
		opt_conf, is_conf = config_yaml.Get("tlsPrivateKeyFile").String()
		value = computeOptionValue("", opt_conf, is_conf, options, "tls-private-key-file")
	} else {
		value = computeOptionValue("", "", errors.New(""), options, "tls-private-key-file")
	}
	if value == "" {
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
	if config_yaml != nil {
		opt_conf, is_conf = config_yaml.Get("authorization").Get("mode").String()
		value = computeOptionValue("AlwaysAllow", opt_conf, is_conf, options, "authorization-mode")
	} else {
		value = computeOptionValue("AlwaysAllow", "", errors.New(""), options, "authorization-mode")
	}
	if value == "AlwaysAllow" {
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
	if config_yaml != nil {
		opt_conf, is_conf = config_yaml.Get("readOnlyPort").String()
		value = computeOptionValue("10255", opt_conf, is_conf, options, "read-only-port")
	} else {
		value = computeOptionValue("10255", "", errors.New(""), options, "read-only-port")
	}
	if value != "0" {
		auditResult := &audit.AuditResult{
			Name:     KubeletReadOnlyPortEnabled,
			Severity: audit.Error,
			Message:  "Read only port is enabled",
			PendingFix: &fixKubeletReadOnlyPortEnabled{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	// (YAML file: protectKernelDefaults: default true)
	if config_yaml != nil {
		opt_conf, is_conf = config_yaml.Get("protectKernelDefaults").String()
		value = computeOptionValue("true", opt_conf, is_conf, options, "protect-kernel-defaults")
	} else {
		value = computeOptionValue("true", "", errors.New(""), options, "protect-kernel-defaults")
	}
	if value != "true" {
		auditResult := &audit.AuditResult{
			Name:     KubeletProtectKernelDefaultsDisabled,
			Severity: audit.Error,
			Message:  "Kernel parameters default value protection is disabled ",
			PendingFix: &fixKubeletProtectKernelDefaultsDisabled{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	// (YAML file: makeIPTablesUtilChains: default true)
	if config_yaml != nil {
		opt_conf, is_conf = config_yaml.Get("makeIPTablesUtilChains").String()
		value = computeOptionValue("true", opt_conf, is_conf, options, "make-iptables-util-chains")
	} else {
		value = computeOptionValue("true", "", errors.New(""), options, "make-iptables-util-chains")
	}
	if value != "true" {
		auditResult := &audit.AuditResult{
			Name:     KubeletMakeIptablesutilChainsDisabled,
			Severity: audit.Error,
			Message:  "Iptables chains is disabled ",
			PendingFix: &fixKubeletMakeIptablesutilChainsDisabled{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	return auditResults
}

// Returne the option value: precdence is: default value then Yaml file then command-line option
func computeOptionValue(def_value string, opt_conf string, is_conf error, options map[string]string, opt_name string) string {
	final_value := def_value

	if is_conf == nil {
		final_value = opt_conf
	}

	opt_val, is_opt := options[opt_name]
	if is_opt {
		final_value = opt_val
	}

	return final_value
}
