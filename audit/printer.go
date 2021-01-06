package audit

import (
	"fmt"
	"io"
	"os"

	"github.com/majeinfo/kubesecaudit/internal/color"
	//"github.com/majeinfo/kubesecaudit/k8stypes"
	"github.com/majeinfo/kubesecaudit/internal/k8s"
	log "github.com/sirupsen/logrus"
)

type Printer struct {
	writer      io.Writer
	minSeverity SeverityLevel
	formatter   log.Formatter
	color       bool
}

type PrintOption func(p *Printer)

func WithMinSeverity(minSeverity SeverityLevel) PrintOption {
	return func(p *Printer) {
		p.minSeverity = minSeverity
	}
}

func WithWriter(writer io.Writer) PrintOption {
	return func(p *Printer) {
		p.writer = writer
	}
}

func WithFormatter(formatter log.Formatter) PrintOption {
	return func(p *Printer) {
		p.formatter = formatter
	}
}

func (p *Printer) parseOptions(opts ...PrintOption) {
	for _, opt := range opts {
		opt(p)
	}
}

func NewPrinter(opts ...PrintOption) Printer {
	p := Printer{
		writer:      os.Stdout,
		minSeverity: Info,
	}
	p.parseOptions(opts...)
	if p.writer == os.Stdout {
		p.color = true
	}
	return p
}

func (p *Printer) PrintReport(report *Report) {
	if p.formatter == nil {
		p.prettyPrintReport(report)
	} else {
		p.logReport(report)
	}
}

func (p *Printer) prettyPrintReport(report *Report) {
	if len(report.ResultsWithMinSeverity(p.minSeverity)) < 1 {
		p.printColor(color.GreenColor, "All checks completed. 0 high-risk vulnerabilities found\n")
	}

	for _, auditResult := range report.ResultsWithMinSeverity(p.minSeverity) {
		severityColor := color.YellowColor
		switch auditResult.Severity {
		case Info:
			severityColor = color.CyanColor
		case Warn:
			severityColor = color.YellowColor
		case Error:
			severityColor = color.RedColor
		}
		p.print("-- ")
		p.printColor(severityColor, "["+auditResult.Severity.String()+"] ")
		p.print(auditResult.Name + "\n")

		if auditResult.Resource != nil {
			p.printColor(color.CyanColor, "   Resource:\n")
			resource := auditResult.Resource
			objectMeta := k8s.GetObjectMeta(*resource)
			typeMeta := k8s.GetTypeMeta(*resource)

			if typeMeta != nil {
				resourceApiVersion, resourceKind := typeMeta.GetObjectKind().GroupVersionKind().ToAPIVersionAndKind()
				if resourceApiVersion != "" && resourceKind != "" {
					p.printColor(color.CyanColor, "     ApiVersion: "+resourceApiVersion+"\n")
					p.printColor(color.CyanColor, "     Kind: "+resourceKind+"\n")
				}
			}

			if objectMeta != nil {
				if objectMeta.GetName() != "" {
					p.printColor(color.CyanColor, "     Name: "+objectMeta.GetName()+"\n")
				}
				if objectMeta.GetNamespace() != "" {
					p.printColor(color.CyanColor, "     Namespace: "+objectMeta.GetNamespace()+"\n")
				}
			}
		}

		p.print("   Message: " + auditResult.Message + "\n")
		if len(auditResult.Metadata) > 0 {
			p.print("   Metadata:\n")
		}
		for k, v := range auditResult.Metadata {
			p.print(fmt.Sprintf("      %s: %s\n", k, v))
		}

		if auditResult.PendingFix != nil {
			p.printColor(color.PurpleColor, "   Suggested Fix:\n")
			p.printColor(color.PurpleColor, "     "+auditResult.PendingFix.Plan()+"\n")
		}

		p.print("\n")
	}
}

func (p *Printer) print(s string) {
	fmt.Fprint(p.writer, s)
}

func (p *Printer) printColor(c string, s string) {
	if p.color {
		fmt.Fprint(p.writer, color.Colored(c, s))
	} else {
		p.print(s)
	}
}

func (p *Printer) logReport(report *Report) {
	resultLogger := log.New()
	resultLogger.SetOutput(p.writer)
	resultLogger.SetFormatter(p.formatter)

	// We manually manage what severity levels to log, logrus should let everything through
	resultLogger.SetLevel(log.DebugLevel)

	for _, auditResult := range report.ResultsWithMinSeverity(p.minSeverity) {
		p.logAuditResult(auditResult, resultLogger)
	}
}

func (p *Printer) logAuditResult(auditResult *AuditResult, baseLogger *log.Logger) {
	logger := baseLogger.WithFields(p.getLogFieldsForResult(auditResult))
	switch auditResult.Severity {
	case Info:
		logger.Info(auditResult.Message)
	case Warn:
		logger.Warn(auditResult.Message)
	case Error:
		logger.Error(auditResult.Message)
	}
}

func (p *Printer) getLogFieldsForResult(auditResult *AuditResult) log.Fields {
	resource := auditResult.Resource
	//apiVersion, kind := resource.GetObjectKind().GroupVersionKind().ToAPIVersionAndKind()
	objectMeta := k8s.GetObjectMeta(*resource)

	fields := log.Fields{
		"AuditResultName":    auditResult.Name,
		//"ResourceKind":       kind,
		//"ResourceApiVersion": apiVersion,
	}

	if objectMeta != nil {
		if objectMeta.GetNamespace() != "" {
			fields["ResourceNamespace"] = objectMeta.GetNamespace()
		}

		if objectMeta.GetName() != "" {
			fields["ResourceName"] = objectMeta.GetName()
		}
	}

	for k, v := range auditResult.Metadata {
		fields[k] = v
	}

	return fields
}



