package main

import (
	"github.com/Thomasdezeeuw/ini"
	"log"
	"os"
)

func configurationParser() string{

	f, err := os.Open("../.env")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	config, err := ini.Parse(f)
	if err != nil {
		log.Fatal()
	}

	var username string
	var password string
	var host     string
	var port     string
	var database string

	username = config[ini.Global]["USER"]
	password = config[ini.Global]["PASSWORD"]
	host =     config[ini.Global]["HOST"]
	port =     config[ini.Global]["PORT"]
	database = config[ini.Global]["DATABASENAME"]

	return username + ":" + password + "@tcp(" + host + ":" + port + ")/" + database
}
