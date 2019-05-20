package main

import (
	"bufio"
	"log"
	"os"
	"path/filepath"
	"strings"
)
func secretparser() string{
	path, err := filepath.Abs("../.env")
	if err != nil {
		log.Fatal(err)
		return "Error loading file."
	}
	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
		return "Error loading file."
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	var username string
	var password string
	var host string
	var port string
	var database string

	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "USER") {
			username = strings.Replace(scanner.Text(), "USER" + "=", "", -1)
		}
		if strings.Contains(scanner.Text(), "PASSWD") {
			password = strings.Replace(scanner.Text(), "PASSWD" + "=", "", -1)
		}
		if strings.Contains(scanner.Text(), "HOST") {
			host = strings.Replace(scanner.Text(), "HOST" + "=", "", -1)
		}
		if strings.Contains(scanner.Text(), "PORT") {
			port = strings.Replace(scanner.Text(), "PORT" + "=", "", -1)
		}
		if strings.Contains(scanner.Text(), "DATABASENAME") {
			database = strings.Replace(scanner.Text(), "DATABASENAME" + "=", "", -1)
		}
	}
	return username + ":" + password + "@tcp(" + host + ":" + port + ")/" + database
}
