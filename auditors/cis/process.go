package cis

import (

	"github.com/prometheus/procfs"
	"strings"
)

type Process struct {
	pname string
	options []string
	envvar []string
}

func GetAllProcesses() ([]Process, error) {
	var processes []Process

	procs, err := procfs.AllProcs()
	if err != nil {
		return processes, err
	}

	for _, proc := range procs {
		cmdLine, err2 := proc.CmdLine()
		if cmdLine == nil || len(cmdLine) < 1 {
			continue
		}
		pgm := cmdLine[0]
		if len(cmdLine) > 1 {
			cmdLine = cmdLine[1:]
		} else {
			cmdLine = []string{}
		}
		if err2 == nil {
			envvar, err := proc.Environ()
			if err != nil {
				envvar = []string{}
			}
			processes = append(processes, Process{pgm, cmdLine, envvar})
		}
	}

	return processes, nil
}

func FindProc(procs []Process, proc_name string) *Process {
	for _, proc := range procs {
		if proc.pname == proc_name || strings.HasSuffix(proc.pname, "/" + proc_name) {
			return &proc
		}
	}
	return nil
}