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
		runAudit(cis.New())(cmd, args)
	},
}

func init() {
	RootCmd.AddCommand(cisCmd)
}

