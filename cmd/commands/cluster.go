package commands

import (
	"github.com/majeinfo/kubesecaudit/auditors/cluster"
	"github.com/spf13/cobra"
)

var appClusterCmd = &cobra.Command{
	Use:   "cluster",
	Short: "Audit K8S cluster configuration",
	Long: `This command checks the cluster configuration, for example, the 
permissions on the files, the options of the apiserver, scheduler, etc...
Example usage:
kubesecaudit cluster`,
	Run: runAudit(cluster.New()),
}

func init() {
	RootCmd.AddCommand(appClusterCmd)
}
