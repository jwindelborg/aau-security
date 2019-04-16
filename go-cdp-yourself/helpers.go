package main

import (
	"encoding/hex"
	"golang.org/x/crypto/sha3"
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
