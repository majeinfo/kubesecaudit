package commands

import (
	"github.com/majeinfo/kubesecaudit/audit"
	"github.com/majeinfo/kubesecaudit/auditors/all"
	"github.com/majeinfo/kubesecaudit/config"
	"github.com/majeinfo/kubesecaudit/internal/k8s"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	apiv1 "k8s.io/api/core/v1"
	"strings"
)

var rootConfig rootFlags

type rootFlags struct {
	format      string
	kubeConfig  string
	manifest    string
	namespace   string
	minSeverity string
	exitCode    int
}

// RootCmd defines the shell command usage for kubeaudit.
var RootCmd = &cobra.Command{
	Use:   "kubesecaudit",
	Short: "A Kubernetes security auditor",
	Long: `Kubesecaudit audits Kubernetes clusters for common security controls.

kubesecaudit will try to connect to a cluster using the local kubeconfig file ($HOME/.kube/config). A different kubeconfig location can be specified using the -c/--kubeconfig flag
`,
}

// Execute is a wrapper for the RootCmd.Execute method which will exit the program if there is an error.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func init() {
	RootCmd.PersistentFlags().StringVarP(&rootConfig.kubeConfig, "kubeconfig", "c", "", "Path to local Kubernetes config file. Only used in local mode (default is $HOME/.kube/config)")
	RootCmd.PersistentFlags().StringVarP(&rootConfig.minSeverity, "minseverity", "m", "info", "Set the lowest severity level to report (one of \"error\", \"warning\", \"info\")")
	RootCmd.PersistentFlags().StringVarP(&rootConfig.format, "format", "p", "pretty", "The output format to use (one of \"pretty\", \"logrus\", \"json\")")
	RootCmd.PersistentFlags().StringVarP(&rootConfig.namespace, "namespace", "n", apiv1.NamespaceAll, "Only audit resources in the specified namespace. Not currently supported in manifest mode.")
	RootCmd.PersistentFlags().StringVarP(&rootConfig.manifest, "manifest", "f", "", "Path to the yaml configuration to audit. Only used in manifest mode.")
	RootCmd.PersistentFlags().IntVarP(&rootConfig.exitCode, "exitcode", "e", 2, "Exit code to use if there are results with severity of \"error\". Conventionally, 0 is used for success and all non-zero codes for an error.")
}

// KubeauditLogLevels represents an enum for the supported log levels.
var KubeauditLogLevels = map[string]audit.SeverityLevel{
	"error":   audit.Error,
	"warn":    audit.Warn,
	"warning": audit.Warn,
	"info":    audit.Info,
}

func runAudit(auditable ...audit.Auditable) func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		report := getReport(auditable...)

		printOptions := []audit.PrintOption{
			audit.WithMinSeverity(KubeauditLogLevels[strings.ToLower(rootConfig.minSeverity)]),
		}

		switch rootConfig.format {
		case "json":
			printOptions = append(printOptions, audit.WithFormatter(&log.JSONFormatter{}))
		case "logrus":
			printOptions = append(printOptions, audit.WithFormatter(&log.TextFormatter{}))
		}


		report.PrintResults(auditAllConfig.ignore_tests, printOptions...)

		//if report.HasErrors() {
		//	os.Exit(rootConfig.exitCode)
		//}
	}
}

func getReport(auditors ...audit.Auditable) *audit.Report {
	auditor := initKubeaudit(auditors...)

	report, err := auditor.AuditLocal(rootConfig.kubeConfig, k8s.ClientOptions{Namespace: rootConfig.namespace})
	if err != nil {
		log.WithError(err).Fatal("Error auditing cluster in local mode")
	}
	return report
}

func initKubeaudit(auditable ...audit.Auditable) *audit.Kubeaudit {
	if len(auditable) == 0 {
		allAuditors, err := all.Auditors(config.KubeauditConfig{})
		if err != nil {
			log.WithError(err).Fatal("Error initializing auditors")
		}
		auditable = allAuditors
	}

	auditor, err := audit.New(auditable)
	if err != nil {
		log.WithError(err).Fatal("Error creating auditor")
	}

	return auditor
}

