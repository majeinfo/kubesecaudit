package all

import (
	"errors"
	"fmt"

	"github.com/majeinfo/kubesecaudit/audit"
	"github.com/majeinfo/kubesecaudit/auditors/capabilities"
	"github.com/majeinfo/kubesecaudit/auditors/cis"
	"github.com/majeinfo/kubesecaudit/auditors/cluster"
	"github.com/majeinfo/kubesecaudit/auditors/image"
	"github.com/majeinfo/kubesecaudit/auditors/limits"
	"github.com/majeinfo/kubesecaudit/config"
)

var ErrUnknownAuditor = errors.New("Unknown auditor")

var AuditorNames = []string{
	capabilities.Name,
	cis.Name,
	cluster.Name,
	image.Name,
	limits.Name,
}

func Auditors(conf config.KubeauditConfig) ([]audit.Auditable, error) {
	enabledAuditors := conf.GetEnabledAuditors()
	if len(enabledAuditors) == 0 {
		enabledAuditors = AuditorNames
	}

	auditors := make([]audit.Auditable, 0, len(enabledAuditors))
	for _, auditorName := range enabledAuditors {
		auditor, err := initAuditor(auditorName, conf)
		if err != nil {
			return nil, err
		}
		auditors = append(auditors, auditor)
	}

	return auditors, nil
}

func initAuditor(name string, conf config.KubeauditConfig) (audit.Auditable, error) {
	switch name {
	case capabilities.Name:
		return capabilities.New(conf.GetAuditorConfigs().Capabilities), nil
	case cis.Name:
		return cis.New(), nil
	case cluster.Name:
		return cluster.New(), nil
	case image.Name:
		return image.New(conf.GetAuditorConfigs().Image), nil
	case limits.Name:
		return limits.New(conf.GetAuditorConfigs().Limits)
	}

	return nil, fmt.Errorf("unknown auditor %s: %w", name, ErrUnknownAuditor)
}

