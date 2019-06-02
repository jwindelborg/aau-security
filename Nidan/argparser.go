package main

import (
	"fmt"
	"log"
	"os"
)

func argParse(args []string) options {
	var helpString = "Options for Nidan:\n" +
		"-h,--help\t\t\tThis\n" +
		"-q\t\t\t\t\tQuiet (Suppress doing domain)\n" +
		"--name [name]\t\tName of scan\n" +
		"-n [500]\t\t\tNumber of Chrome instances\n" +
		"-p [9222]\t\t\tCDP Port\n" +
		"-w [worker]\t\t\tWorker name. Default: $HOST\n" +
		"--no-scan\t\t\tVisit domains without scanning\n" +
		"--pb\t\t\t\tDo Privacy Badger\n" +
		"--old\t\t\t\tScan already visited\n" +
		"--random\t\t\tOrder queue random\n" +
		"--no-headers\t\tNo HTTP headers\n" +
		"--cdp-name [chrome]\tName of chrome/chromium\n"

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
				log.Fatal("Please specify a name")
			}
		case "-p":
			if len(args) > i {
				options.port = args[i+1]
			} else {
				log.Fatal("Please specify a port value")
			}
		case "-w":
			if len(args) > i {
				options.worker = args[i+1]
			} else {
				log.Fatal("Please specify a worker name")
			}
		case "--chromium-name":
			if len(args) > i {
				options.chromeName = args[i+1]
			} else {
				log.Fatal("Please specify a chromium application name")
			}
		case "-n":
			if len(args) > i {
				var nr int
				if _, err := fmt.Sscanf(args[i+1], "id:%5d", &nr); err == nil {
					fmt.Println(i)
				}
				options.queueSize = uint(nr)
			}
		}
	}

	return options
}
