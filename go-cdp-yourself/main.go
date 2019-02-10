package main

import (
	"context"
	"database/sql"
	"debug/dwarf"
	"encoding/base64"
	"encoding/hex"
	"github.com/chromedp/cdproto/profiler"
	"github.com/chromedp/cdproto/security"
	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/runner"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/sha3"
	_ "golang.org/x/crypto/sha3"
	"io/ioutil"
	_ "io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type Domain struct {
	domain string
	id int
}

func main() {
	var err error

	ctxt, cancel := context.WithCancel(context.Background())
	defer cancel()

	db, err := sql.Open("mysql", "aau:2387AXumK52aeaSA@tcp(85.191.223.61:3306)/aau")
	if err != nil {
		log.Fatal(err)
	}

	domains := loadDomainsDB(ctxt, *db)

	c, err := chromedp.New(ctxt,
		chromedp.WithRunnerOptions(
			runner.ProxyServer("http://127.0.0.1:8080"), // enable for mitmproxy or Burp
			runner.Flag("headless", true),    // enable for server, disable for local debug
			runner.Flag("no-sandbox", true),
		),
		chromedp.WithLog(log.Printf), // Verbose output
	)
	if err != nil {
		log.Fatal(err)
	}

	for i := 0; i < len(domains) - 1; i++ {
		doDomain(ctxt, c, *db, domains[i])
	}

	err = c.Shutdown(ctxt)
	if err != nil {
		log.Fatal(err)
	}

	err = c.Wait()
	if err != nil {
		log.Fatal(err)
	}
}

func doDomain(ctxt context.Context,c *chromedp.CDP, db sql.DB, domain Domain) dwarf.VoidType {
	var err error
	var tasks chromedp.Tasks
	var title string
	var resJSbase64 string

	log.Printf("Doing domain: " + domain.domain)

	// TODO: Find a way to access DevTools network tab
	tasks = append(tasks, chromedp.Tasks{
		security.SetIgnoreCertificateErrors(true), // if intercept with burp or mitmproxy certificate is not signed
		// TODO: Find a way to access profiler data, it gives specific knowledge about run JavaScript
		profiler.Enable(),
		profiler.Start(),
		profiler.StartPreciseCoverage(),
		chromedp.Navigate("http://" + domain.domain),
		chromedp.Sleep(10*time.Second),
		chromedp.Stop(),
		chromedp.Title(&title),
		chromedp.EvaluateAsDevTools("var scri = []; for (var index = 0; index < document.getElementsByTagName('script').length; index++) { scri[index] = (document.getElementsByTagName('script')[index].outerHTML.toString()); }; btoa(unescape(encodeURIComponent(scri.join('::,,//'))));", &resJSbase64),
									// var script = []
									// var scriptObj = document.getElementByTagName('script')
									// for (var index = 0; index < scriptObj; index++) {
									//   script[i] = (script.Obj.outerHTML.ToString());
									// }
									// btoa(unescape(encodeURIComponent(script.join('::,,//')))));
	})
	// Consider setting a flag between sites for mitmproxy
	//   navigate(Domain.id + ".arpa") or similar

	err = c.Run(ctxt, chromedp.Tasks{tasks})
	if err != nil {
		log.Printf("Could not process domain: " + domain.domain)
		return dwarf.VoidType{}
	}

	sqlStmt := `UPDATE domains SET title = ? WHERE domain_id = ?;`
	_, err = db.Exec(sqlStmt, title, domain.id)
	if err != nil {
		log.Printf("Error: Could not set title for: " + domain.domain)
	}

	resJSbase64Decoded, err := base64.StdEncoding.DecodeString(resJSbase64)
	if err != nil {
		log.Printf("Could not decode javascript for: " + domain.domain)
		return dwarf.VoidType{}
	}
	scripts := strings.Split(string(resJSbase64Decoded),"::,,//")

	// TODO: Refactor for loop: Simplify logic
	for _, element := range scripts {
		findScriptRegex := regexp.MustCompile(`<script\s+[^>]*?src=(("|')([^"']+))`)

		if !findScriptRegex.MatchString(element) {
			shabytes := sha3.Sum256([]byte(element))
			sha := hex.EncodeToString(shabytes[:])
			sqlJavaScriptInsert := `INSERT INTO javascript (script, javascript_checksum) VALUES (?, ?);`
			_, err = db.Exec(sqlJavaScriptInsert, element, sha)
			sqlJavaScriptRelationInsert := `INSERT INTO javascriptdomain (javascript_checksum, domain_id) VALUES (?, ?);`
			_, err = db.Exec(sqlJavaScriptRelationInsert, sha, domain.id)
		} else {
			scriptURL := findScriptRegex.FindStringSubmatch(element)[3]
			scriptURL = prepareScriptURL(domain.domain, scriptURL)

			response, err := http.Get(scriptURL)
			if err != nil {
				log.Printf("Error getting http request for js file: " + scriptURL)
			} else {
				if response.StatusCode >= 200 && response.StatusCode < 400 {
					body, err := ioutil.ReadAll(response.Body)
					if err != nil {
						log.Printf("Error reading body for js file")
						return dwarf.VoidType{}
					} else {
						defer response.Body.Close()
					}
					element = string(body)
				} else {
					element = string(response.StatusCode)
				}
			}
			shabytes := sha3.Sum256([]byte(element))
			sha := hex.EncodeToString(shabytes[:])
			sqlJavaScriptInsert := `INSERT INTO javascript (script, javascript_checksum) VALUES (?, ?);`
			_, err = db.Exec(sqlJavaScriptInsert, element, sha)
			if err != nil {
				log.Printf("Could not insert javascript to database for: " + domain.domain)
				return dwarf.VoidType{}
			}
			sqlJavaScriptRelationInsert := `INSERT INTO javascriptdomain (javascript_checksum, domain_id) VALUES (?, ?);`
			_, err = db.Exec(sqlJavaScriptRelationInsert, sha, domain.id)
			if err != nil {
				log.Printf("Could not insert javascript to database for: " + domain.domain)
				return dwarf.VoidType{}
			}
		}
	}

	return dwarf.VoidType{}
}

func loadDomainsDB(ctxt context.Context, db sql.DB) []Domain {
	rows, err := db.QueryContext(ctxt, "SELECT domain_id, domain FROM domains")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	domains := []Domain{}

	for rows.Next() {
		var (
			id int
			domain string
		)
		if err := rows.Scan(&id, &domain); err != nil {
			log.Fatal(err)
		}
		tmpDom := Domain{
			id: id,
			domain: strings.TrimSpace(domain),
		}
		domains = append(domains, tmpDom)
	}

	return domains
}

func prepareScriptURL(domain string, url string) string {
	url = strings.TrimSpace(url)
	if strings.Contains(url, "\n") {
		url = strings.Trim(url, "\n")
	}

	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url,"https://") {
		return url
	} else if strings.HasPrefix(url,"//") {
		return "http://" + domain + url
	} else {
		return "http://" + domain + url
	}
}

func loadDomains(filename string) []string  {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	lines := strings.Split(string(content), "\n")
	return lines
}