package commands

import (
	"os"

	"github.com/majeinfo/kubesecaudit/auditors/all"
	"github.com/majeinfo/kubesecaudit/config"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var auditAllConfig struct {
	configFile string
	ignore_tests []string
}

func GetIgnoreTests() []string {
	return auditAllConfig.ignore_tests
}

func auditAll(cmd *cobra.Command, args []string) {
	conf := loadKubeAuditConfigFromFile(auditAllConfig.configFile)

	// Config options set via flags override the config file
	conf = setConfigFromFlags(cmd, conf)

	auditors, err := all.Auditors(conf)
	if err != nil {
		log.WithError(err).Fatal("Error creating auditors")
	}

	runAudit(auditors...)(cmd, args)
}

func setConfigFromFlags(cmd *cobra.Command, conf config.KubeauditConfig) config.KubeauditConfig {
	flagset := cmd.Flags()
	for _, item := range []struct {
		flag      string
		flagVal   string
		configVal *string
	}{
		{"image", imageConfig.Image, &conf.AuditorConfig.Image.Image},
		{"cpu", limitsConfig.CPU, &conf.AuditorConfig.Limits.CPU},
		{"memory", limitsConfig.Memory, &conf.AuditorConfig.Limits.Memory},
	} {
		if flagset.Changed(item.flag) {
			*item.configVal = item.flagVal
		}
	}

	if flagset.Changed("drop") {
		conf.AuditorConfig.Capabilities.DropList = capabilitiesConfig.DropList
	}

	return conf
}

func loadKubeAuditConfigFromFile(configFile string) config.KubeauditConfig {
	if configFile == "" {
		return config.KubeauditConfig{}
	}

	reader, err := os.Open(configFile)
	if err != nil {
		log.WithError(err).Fatal("Unable to open config file ", configFile)
	}

	conf, err := config.New(reader)
	if err != nil {
		log.WithError(err).Fatal("Error parsing config file ", configFile)
	}

	return conf
}

var auditAllCmd = &cobra.Command{
	Use:   "all",
	Short: "Run all audits",
	Long: `Run all audits

Example usage:
kubesecaudit all -f /path/to/yaml
kubesecaudit all -k /path/to/kubesecaudit-config.yaml /path/to/yaml
`,
	Run: auditAll,
}

func init() {
	RootCmd.AddCommand(auditAllCmd)
	auditAllCmd.Flags().StringVarP(&auditAllConfig.configFile, "kconfig", "k", "", "Path to kubesecaudit config")
	auditAllCmd.Flags().StringSliceVarP(&auditAllConfig.ignore_tests, "ignore", "", []string{}, "Comma separated list on Tests to ignore")

	setImageFlags(auditAllCmd)
	setLimitsFlags(auditAllCmd)
	setCapabilitiesFlags(auditAllCmd)
}

