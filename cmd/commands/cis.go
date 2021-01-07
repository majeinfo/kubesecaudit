package commands

import (
	"fmt"
	"github.com/majeinfo/kubesecaudit/auditors/cis"
	"github.com/spf13/cobra"
)

var cisConfig cis.Config

var cisCmd = &cobra.Command{
	Use:     "cis",
	Aliases: []string{"cis"},
	Short:   "Audit nodes with CIS Benchmark Rules",
	Long: fmt.Sprintf(`
Example usage:
kubeaudit cis`),
	Run: func(cmd *cobra.Command, args []string) {
		conf := loadKubeAuditConfigFromFile(auditAllConfig.configFile)

		// Config options set via flags override the config file
		conf = setConfigFromFlags(cmd, conf)

		runAudit(cis.New(conf.GetAuditorConfigs().Cis))(cmd, args)
	},
}

func init() {
	RootCmd.AddCommand(cisCmd)
	cisCmd.Flags().StringVarP(&auditAllConfig.configFile, "kconfig", "k", "", "Path to kubeaudit config")
	cisCmd.Flags().StringVarP(&auditAllConfig.ignore_tests, "ignore", "", "", "Comma separated list on Tests to ignore")
}

