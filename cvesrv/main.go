package main

import (
	"encoding/json"
	"github.com/Thomasdezeeuw/ini"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"unicode"
)

type search struct {
	Server  string
	Version string
	APIKey  string
}

type searchResponse struct {
	CVE []string
}

type searchCVE struct {
	CVE    string
	APIKey string
}

type cveResponse struct {
	CVE     string
	CVSS    float64
	Summary string
}

func main() {
	http.HandleFunc("/search/", lookupCVE)
	http.HandleFunc("/cve/", returnCVE)

	if err := http.ListenAndServe(":9876", nil); err != nil {
		panic(err)
	}
}

func runSearchCommand(server string, version string) searchResponse {
	out, err := exec.Command("/root/cve-search/bin/search.py",
		"-p", server + ":" + version,
		"-o", "cveid",
		"--only-if-vulnerable").Output()
	if err != nil {
		log.Print(err)
	}
	outList := strings.Split(string(out), "\n")
	var realList []string
	for _,str := range outList {
		if str != "" {
			realList = append(realList, str)
		}
	}

	return searchResponse {
		CVE: realList,
	}

}

func runCVECommand(cve string) cveResponse {
	stdout, err := exec.Command("/root/cve-search/bin/search.py",
		"-c", cve,
		"-o", "csv").Output()
	if err != nil {
		return cveResponse{}
	}

	output := strings.Split(string(stdout), "|")
	cvss, err := strconv.ParseFloat(output[2], 64)
	if err != nil {
		return cveResponse{}
	}

	return cveResponse{
		CVE:     output[0],
		CVSS:    cvss,
		Summary: output[3],
	}
}

func isValidServer(server string) bool {
	for _, r := range server {
		if !unicode.IsLetter(r) &&
			!unicode.IsNumber(r) &&
			r != '_' &&
			r != ':' {
			return false
		}
	}
	return true
}

func isValidVersion(version string) bool {
	for _, r := range version {
		if !unicode.IsLetter(r) &&
			!unicode.IsNumber(r) &&
			r != '.' &&
			r != '-' {
			return false
		}
	}
	return true
}

/* Verify CVE
 * Valid CVE example: CVE-2014-4725
 * Structure always CVE-YYYY-NNNN
 * The last numbers is an ID with
 * variable length.
 */
func isValidCVE(cve string) bool {

	if len(cve) <= 10 || len(cve) >= 20 {
		return false
	}

	if cve[0:4] != "CVE-" || cve[8:9] != "-" {
		return false
	}

	// We could be more pedantic and say
	// every year must start with a '1' or a '2'
	for _ ,n := range cve[4:8] {
		if !unicode.IsNumber(n) {
			return false
		}
	}

	for _, n := range cve[9:] {
		if !unicode.IsNumber(n) {
			return false
		}
	}

	return true
}

func lookupCVE(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var q search
	err := decoder.Decode(&q)
	if err != nil {
		log.Print(err)
		return
	}

	// We don't want to waste resources answering other peoples queries
	if q.APIKey != apiKeyFetch() {
		return
	}

	if !isValidServer(q.Server) {
		return
	}

	if !isValidVersion(q.Version) {
		return
	}

	answer := runSearchCommand(q.Server, q.Version)

	err = json.NewEncoder(w).Encode(answer)
	if err != nil { log.Print(err) }
}

func returnCVE(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var q searchCVE
	err := decoder.Decode(&q)
	if err != nil {
		log.Print("Decode error")
		log.Print(err)
		return
	}

	// We don't want to waste resources answering other peoples queries
	if q.APIKey != apiKeyFetch() {
		return
	}

	if !isValidCVE(q.CVE) {
		return
	}

	answer := runCVECommand(q.CVE)

	err = json.NewEncoder(w).Encode(answer)
	if err != nil { log.Print(err) }
}

func apiKeyFetch() string {
	f, err := os.Open("../.env")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	config, err := ini.Parse(f)
	if err != nil {
		log.Fatal()
	}

	return config[ini.Global]["KEY"]
}