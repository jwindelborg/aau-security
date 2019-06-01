package main

import (
	"fmt"
	"log"
	"os"
)

func argParse(args []string) options {
	var helpString = "Options for Nidan scanner:\n" +
		"-h,--help\t\tThis\n" +
		"-q\t\t\tQuite (suppress doing domain)\n" +
		"--name [name]\t\tName of scan\n" +
		"-n [500]\t\tNumber of Chrome instances" +
		"-p [9222]\t\tPort default 9222\n" +
		"-w [worker]\t\tWorker default $HOST\n" +
		"--no-scan\t\tDon't scan\n" +
		"--pb\t\t\tDo Privacy Badger\n" +
		"--old\t\t\tScan already visited\n" +
		"--random\t\tOrder queue random\n" +
		"--no-headers\t\tNo HTTP headers\n" +
		"--cdp-name[chromium]\tName of chrome/chromium\n"

	var options options
	options.scanLabel = "unnamed"
	options.port = "9222"
	options.worker, _ = os.Hostname()
	options.doScan = true
	options.doPB = false
	options.scanOld = false
	options.random = false
	options.quite = false
	options.doHeaders = true
	options.queueSize = 500
	options.chromeName = guessDefaultChromiumName()

	for i, arg := range args {
		switch arg {
		case "--help", "-h":
			fmt.Print(helpString)
			os.Exit(0)
		case "--no-scan":
			options.doScan = false
		case "--no-pb":
			options.doPB = false
		case "--old":
			options.scanOld = true
		case "--random":
			options.random = true
		case "--no-headers":
			options.doHeaders = false
		case "-q":
			options.quite = true
		case "--name":
			if len(args) > i {
				options.scanLabel = args[i+1]
			} else {
				log.Fatal("You didn't specify a name")
			}
		case "-p":
			if len(args) > i {
				options.port = args[i+1]
			} else {
				log.Fatal("You need to specify a port value")
			}
		case "-w":
			if len(args) > i {
				options.worker = args[i+1]
			} else {
				log.Fatal("You need to specify a worker name")
			}
		case "--chromium-name":
			if len(args) > i {
				options.chromeName = args[i+1]
			} else {
				log.Fatal("You need to specify a chromium application name")
			}
		case "-n":
			if len(args) > i {
				var nr int
				if _, err := fmt.Sscanf(args[i+1], "id:%5d", &nr); err == nil {
					fmt.Println(i) // Outputs 123
				}
				options.queueSize = uint(nr)
			}
		}
	}

	return options
}