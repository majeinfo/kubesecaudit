package commands

import (
	"github.com/majeinfo/kubesecaudit/auditors/seccomp"
	"github.com/spf13/cobra"
)

var seccompCmd = &cobra.Command{
	Use:   "seccomp",
	Short: "Audit containers running without Seccomp",
	Long: `This command determines which containers are running without Seccomp enabled.
An ERROR result is generated when a container has Seccomp disabled or misconfigured.
Example usage:
kubesecaudit seccomp`,
	Run: runAudit(seccomp.New()),
}

func init() {
	RootCmd.AddCommand(seccompCmd)
}
