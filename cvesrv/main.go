package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"unicode"
)

type question struct {
	Server string
	Version string
	APIKey string
}

type response struct {
	CVE []string
}

func main() {
	http.HandleFunc("/", lookupCVE)

	if err := http.ListenAndServe(":9876", nil); err != nil {
		panic(err)
	}
}

func runSubCommand(server string, version string) response {
	out, err := exec.Command("/root/cve-search/bin/search.py",
		"-p", server + ":" + version,
		"-o", "cveid",
		"--only-if-vulnerable").Output()
	if err != nil {
		log.Print("Problem, we can't run this")
		log.Print(err)
	}
	outList := strings.Split(string(out), "\n")
	var realList []string
	for _,str := range outList {
		if str != "" {
			realList = append(realList, str)
		}
	}

	return response {
		CVE: realList,
	}

}

func validServer(server string) bool {
	for _, r := range server {
		if !unicode.IsLetter(r) &&
			!(r >= 0x30 && r <= 0x39) &&
			r != 0x5f {
			return false
		}
	}
	return true
}

func validVersion(version string) bool {
	for _, r := range version {
		if !unicode.IsLetter(r) &&
			r != 0x2e &&
			!(r >= 0x30 && r <= 0x39) {
			return false
		}
	}
	return true
}

func lookupCVE(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var q question
	err := decoder.Decode(&q)
	if err != nil {
		log.Print(err)
		return
	}

	// We don't want to waste resources answering other peoples queries
	if q.APIKey != "2MdW6E3dEXKasutaskRhmDhW99XP5bAWKewk9EMPZFG7T" {
		return
	}

	if !validServer(q.Server) {
		return
	}

	if !validVersion(q.Version) {
		return
	}

	answer := runSubCommand(q.Server, q.Version)

	err = json.NewEncoder(w).Encode(answer)
	if err != nil { log.Print(err) }
}