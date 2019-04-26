package main

import (
	"fmt"
	"log"
	"os"
)

func argParse(args []string) options {
	var helpString = "Options for Nidan scanner:\n" +
		"-h,--help\tThis\n" +
		"-q\t\tQuite (suppress doing domain)\n" +
		"--name [name]\tName of scan\n" +
		"-p [9222]\tPort default 9222\n" +
		"-w [worker]\tWorker default $HOST\n" +
		"--no-scan\tDon't scan\n" +
		"--no-pb\t\tNo Privacy Badger\n" +
		"--old\t\tScan already visited\n" +
		"--random\tOrder queue random\n" +
		"--no-headers\tNo HTTP headers\n" +
		"--chromium-name[chromium]\tName of chrome/chromium\n"

	var options options
	options.scanLabel = "unnamed"
	options.port = "9222"
	options.worker, _ = os.Hostname()
	options.doScan = true
	options.doPB = true
	options.scanOld = false
	options.random = false
	options.quite = false
	options.doHeaders = true
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
				log.Fatal("You have as many braincells as you have port values")
			}
		case "-w":
			if len(args) > i {
				options.worker = args[i+1]
			} else {
				log.Fatal("You have as many braincells as you have worker names")
			}
		case "--chromium-name":
			if len(args) > i {
				options.chromeName = args[i+1]
			} else {
				log.Fatal("You are pretty stupid")
			}
		}
	}

	return options
}