package main

import (
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/sha3"
	"log"
	"net/http"
	"os/exec"
	"strings"
)

func prepareScriptURL(domain string, url string) string {
	url = strings.TrimSpace(url)
	if strings.Contains(url, "\n") {
		url = strings.Trim(url, "\n")
	}

	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url,"https://") {
		return url
	} else if strings.HasPrefix(url,"//") {
		return "http://" + url[2:]
	} else {
		if strings.HasPrefix(url, "/") {
			return "http://" + domain + url
		} else {
			return "http://" + domain + "/" + url
		}
	}
}

func boolToInt(bo bool) int {
	if bo {
		return 1
	} else {
		return 0
	}
}

func sha3FromStr(str string) string {
	shaBytes := sha3.Sum256([]byte(str))
	return hex.EncodeToString(shaBytes[:])
}

func getHttpHeaders(url string) string {
	// TODO: This can fail, our program behaves like curl:
	//  curl -I https://www.nordnet.dk/start.html     --> curl: (52) Empty reply from server = death
	//  curl -I https://www.nordnet.dk/start.html:443 --> normal HTTP headers (not tested in Go)
	//  we can handle both HTTP and HTTPS, something else breaks it

	resp, err := http.Head(url)
	if err != nil {
		log.Print("Could not get http header")
		return ""
	}
	defer resp.Body.Close()

	var res []string
	for name, values := range resp.Header {
		for _, value := range values {
			res = append(res, fmt.Sprintf("%s: %s", name, value))
		}
	}

	if len(res) < 1 {
		return ""
	}

	var s string
	for _, header := range res {
		s = s + header + "\n"
	}
	return s
}

func guessDefaultChromiumName() string {
	cmd := exec.Command("uname", "-a")
	stdout, err := cmd.Output()
	if err != nil {
		return "chromium"
	}

	// On Arch Linux chromium is called chromium
	if strings.Contains(strings.ToLower(string(stdout)), "arch") {
		return "chromium"
	}

	// On Ubuntu Linux chromium is called chromium-browser
	if strings.Contains(strings.ToLower(string(stdout)), "ubuntu") {
		return "chromium-browser"
	}

	// If we have no clue we guess
	return "chromium-browser"

}