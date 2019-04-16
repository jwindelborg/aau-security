package main

import (
	"fmt"
	"log"
	"os"
)

func argParse(args []string) options {
	var helpString = "Options for Nidan scanner:\n-h,--help\tThis\n-p [9222]\tPort default 9222\n-w [worker]\tWorker default $HOST\n--dk\t\tDefault DB\n--alexaDB\tAlexa DB\n--nidan\t\tNidan DB\n--no-scan\tDon't scan\n--no-pb\t\tNo Privacy Badger\n"
	var options options

	options.dbName = "aau"
	options.port = "9222"
	options.worker, _ = os.Hostname()
	options.doScan = true
	options.doPB = true

	for i, arg := range args {
		switch arg {
		case "--help", "-h":
			fmt.Print(helpString)
			os.Exit(0)
		case "--alexa":
			options.dbName = "alexaDB"
		case "--dk":
			options.dbName = "aau"
		case "--nidan":
			options.dbName = "nidan"
		case "--no-scan":
			options.doScan = false
		case "--no-pb":
			options.doPB = false
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
		}
	}

	return options
}