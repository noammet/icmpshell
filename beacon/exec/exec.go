package execution

import (
	"log"
	"os/exec"
	"runtime"
)

//gotta redo this
// new plan MODULARITY is the name of the game
// this will revolve around the universal go loader lib
// lets say you want to change encryption schemes from PAKE to TLS you can do that on the fly
//or from TCP to UDP to DNS

// RunCMD executes a command with cmd.exe
func RunCMD(cmd string) ([]byte, error) {
	var c *exec.Cmd
	if runtime.GOOS == "windows" {
		log.Println("Windows is getting executed")
		c = exec.Command("cmd.exe", "/C", cmd)
	} else {
		log.Println("linux is getting executed")
		c = exec.Command("/bin/sh", "-c", cmd)
	}
	output, err := c.CombinedOutput()
	if err != nil {
		return nil, err
	}
	return output, err

}
