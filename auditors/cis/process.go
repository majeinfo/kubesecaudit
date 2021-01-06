package cis

import (
	"bytes"
	"fmt"
	"os/exec"
)

type Process struct {
	pname string
	options []string
}

func Processes() ([]Process, error) {
	var processes []Process

	var out bytes.Buffer
	cmd := exec.Command("/bin/ps", "-edf")
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return processes, err
	}
	fmt.Printf(out.String())

	return processes, nil
}