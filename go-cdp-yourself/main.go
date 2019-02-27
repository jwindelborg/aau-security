package main

import (
	"context"
	"database/sql"
	"debug/dwarf"
	"encoding/hex"
	"github.com/anaskhan96/soup"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
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
	"os"
	"strings"
	"time"
)

type Domain struct {
	domain string
	id int
}

type DomainCookie struct {
	name     string
	domain   string
	value    string
	expires  float64
	httpOnly int
	secure   int
}

func main() {
	var err error

	ctxt, cancel := context.WithCancel(context.Background())
	defer cancel()

	c, err := chromedp.New(ctxt,
		chromedp.WithRunnerOptions(
			//runner.ProxyServer("http://127.0.0.1:8080"), // enable for mitmproxy or Burp
			runner.Flag("headless", true),    // enable for server, disable for local debug
			runner.Flag("no-sandbox", true),
		),
		chromedp.WithLog(log.Printf), // Verbose output
	)
	if err != nil {
		log.Fatal(err)
	}

	keepRunning := true

	for keepRunning {
		domains := loadDomainQueue(ctxt)

		for i := 0; i < len(domains) - 1; i++ {
			ctxDomain, cancelDomain := context.WithTimeout(context.Background(), 100*time.Second)
			doDomain(ctxDomain, c, domains[i])
			cancelDomain()
		}

		domainVisitHistory()
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

func doDomain(ctxt context.Context,c *chromedp.CDP, domain Domain) dwarf.VoidType {
	var err error
	var tasks chromedp.Tasks
	var title string
	var cookies []DomainCookie
	var html string

	log.Printf("Doing domain: " + domain.domain)

	db, err := sql.Open("mysql", "aau:2387AXumK52aeaSA@tcp(85.191.223.61:3306)/aau")
	db.SetMaxIdleConns(15)
	db.SetConnMaxLifetime(60 * time.Second)
	if err != nil {
		log.Fatal(err)
	}

	// TODO: Find a way to access DevTools network tab
	tasks = append(tasks, chromedp.Tasks{
		network.ClearBrowserCookies(),
		network.ClearBrowserCache(),
		security.SetIgnoreCertificateErrors(true), // if intercept with burp or mitmproxy certificate is not signed
		// TODO: Find a way to access profiler data, it gives specific knowledge about run JavaScript
		//profiler.Enable(),
		//profiler.Start(),
		//profiler.StartPreciseCoverage(),
		chromedp.Navigate("http://" + domain.domain),
		chromedp.Sleep(10*time.Second),
		chromedp.Stop(),
		chromedp.Title(&title),
		chromedp.EvaluateAsDevTools("document.documentElement.outerHTML.toString()", &html),

		chromedp.ActionFunc(func(ctxt context.Context, h cdp.Executor) error {
			cookiesObj, err := network.GetAllCookies().Do(ctxt, h)
			if err != nil {
				return err
			}

			for _, cookie := range cookiesObj {
				tmpCookie := DomainCookie{
					name:     cookie.Name,
					domain:   cookie.Domain,
					expires:  cookie.Expires,
					httpOnly: boolToInt(cookie.HTTPOnly),
					secure:   boolToInt(cookie.Secure),
					value:    cookie.Value,
				}
				cookies = append(cookies, tmpCookie)
			}

			return nil
		}),
	})

	// Consider setting a flag between sites for mitmproxy

	err = c.Run(ctxt, chromedp.Tasks{tasks})
	if err != nil {
		log.Printf("doDomain: c.Run() could not process domain: " + domain.domain)
		return dwarf.VoidType{}
	}

	sqlStmt := `UPDATE domains SET title = ? WHERE domain_id = ?;`
	_, err = db.Exec(sqlStmt, title, domain.id)
	if err != nil {
		log.Printf("doDomain: Could not update title for: " + domain.domain)
	}

	for _, cookie := range cookies {
		sqlInsertCookie := `INSERT INTO cookies (domain_id, cookie_name, cookie_value, cookie_domain, cookie_expire, is_secure, is_http_only) VALUES (?, ?, ?, ?, ?, ?, ?);`
		_, err = db.Exec(sqlInsertCookie, domain.id, cookie.name, cookie.value, cookie.domain, cookie.expires, cookie.secure, cookie.httpOnly)
		if err != nil {
			log.Printf("doDomain: Could not set cookie")
		}
	}

	htmlDomObject := soup.HTMLParse(html)
	javascripts := htmlDomObject.FindAll("script")
	for _, js := range javascripts {
		if js.Attrs()["src"] != "" {
			scriptURL := prepareScriptURL(domain.domain, js.Attrs()["src"])
			response, err := http.Get(scriptURL)
			if err != nil {
				log.Printf("doDomain: Could not fetch external script: " + scriptURL)
				continue
			}
			if response.StatusCode >= 200 && response.StatusCode < 400 {
				body, err := ioutil.ReadAll(response.Body)
				if err != nil {
					log.Printf("doDomain: Could not get response body for external script: " + scriptURL)
					continue
				} else {
					err := response.Body.Close()
					if err != nil {
						log.Printf("doDomain: There was an error closing body for external script: " + scriptURL)
						continue
					}
					sqlJs := `INSERT INTO javascripts (script, url) VALUES (?, ?);`
					_, err = db.Exec(sqlJs, string(body), scriptURL)
					if err != nil {
						log.Printf("doDomain: Error inserting JS into DB for external script: " + scriptURL)
					}
					sqlJsRel := `INSERT INTO javascriptdomains (domain_id, url, is_external) VALUES (?, ?, ?);`
					_, err = db.Exec(sqlJsRel, domain.id, scriptURL, 1)
					if err != nil {
						log.Printf("doDomain: Could not insert JS relation into DB for external script: " + scriptURL)
					}
				}

			}
		} else {
			shaBytes := sha3.Sum256([]byte(js.Text()))
			sha := "/" + hex.EncodeToString(shaBytes[:])
			generatedUrl := prepareScriptURL(domain.domain, sha)
			sqlJs := `INSERT INTO javascripts (script, url) VALUES (?, ?);`
			_, err = db.Exec(sqlJs, js.Text(), generatedUrl)
			if err != nil {
				log.Printf("doDomain: Could not insert clean JS into DB for internal script: " + generatedUrl)
			}
			sqlJsRel := `INSERT INTO javascriptdomains (domain_id, url, is_external) VALUES (?, ?, ?);`
			_, err = db.Exec(sqlJsRel, domain.id, generatedUrl, 0)
			if err != nil {
				log.Printf("doDomain: Could not insert clean JS relation into DB for internal script: " + generatedUrl)
			}
		}
	}

	err = db.Close()
	if err != nil {
		log.Fatal("doDomain: DC conn could not be closed")
	}
	return dwarf.VoidType{}
}

func loadDomainQueue(ctxt context.Context) []Domain {
	hostname, err := os.Hostname()

	db, err := sql.Open("mysql", "aau:2387AXumK52aeaSA@tcp(85.191.223.61:3306)/aau")
	db.SetMaxIdleConns(15)
	db.SetConnMaxLifetime(60 * time.Second)
	if err != nil {
		log.Fatal(err)
	}

	cleanstmt := `DELETE FROM lockeddomains WHERE worker = ?`
	_, err = db.Exec(cleanstmt, hostname)
	if err != nil {
		log.Printf("LoadDomainQueue: Could not delete from locked")
	}

	lockstmt := `INSERT IGNORE INTO lockeddomains (domain_id, worker, locked_time) SELECT domains.domain_id, ? AS 'worker', NOW() FROM domains WHERE domain_id NOT IN (SELECT domain_id FROM lockeddomains) AND domain_id NOT IN (SELECT domain_id FROM domainvisithistory) ORDER BY RAND() LIMIT 2500;`
	_, err = db.Exec(lockstmt, hostname)
	if err != nil {
		log.Printf("LoadDomainQueue: Could not lock domains")
	}

	rows, err := db.QueryContext(ctxt, "SELECT domain_id, domain FROM domains WHERE domain_id IN (SELECT domain_id FROM lockeddomains WHERE worker = ?);", hostname)
	if err != nil {
		log.Fatal(err)
	}

	var domains []Domain

	for rows.Next() {
		var (
			id int
			domain string
		)
		if err := rows.Scan(&id, &domain); err != nil {
			log.Fatal(err)
		}
		tmpDomain := Domain{
			id: id,
			domain: strings.TrimSpace(domain),
		}

		domains = append(domains, tmpDomain)
	}
	err = rows.Close()
	if err != nil {
		log.Fatal("LoadDomainsDB: Could not close rows")
	}
	err = db.Close()
	if err != nil {
		log.Fatal("LoadDomainsDB: Could not close DB conn")
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

func boolToInt(bo bool) int {
	if bo {
		return 1
	} else {
		return 0
	}
}

func domainVisitHistory() dwarf.VoidType {
	hostname, err := os.Hostname()
	db, err := sql.Open("mysql", "aau:2387AXumK52aeaSA@tcp(85.191.223.61:3306)/aau")
	db.SetMaxIdleConns(15)
	db.SetConnMaxLifetime(60 * time.Second)
	if err != nil {
		log.Fatal(err)
	}

	stmt := `INSERT IGNORE INTO domainvisithistory (domain_id, worker, time_processed) SELECT domain_id, ?, NOW() FROM lockeddomains WHERE worker = ?;`
	_, err = db.Exec(stmt, hostname, hostname)
	if err != nil {
		log.Printf("domainVisitHistory: Could not update history")
	}
	stmt2 := `DELETE FROM lockeddomains WHERE worker = ?;`
	_, err = db.Exec(stmt2, hostname)
	if err != nil {
		log.Printf("domainVisitHistory: Could not delete locks")
	}

	return dwarf.VoidType{}
}

func putdomainstodb(filename string) dwarf.VoidType  {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	lines := strings.Split(string(content), "\n")

	db, err := sql.Open("mysql", "aau:2387AXumK52aeaSA@tcp(85.191.223.61:3306)/aau")
	if err != nil {
		log.Fatal(err)
	}

	for _, line := range lines {
		sqlInsertCookie := `INSERT INTO domains (domain, title) VALUES (?, ?);`
		_, err = db.Exec(sqlInsertCookie, line, "")
		if err != nil {
			log.Printf("Shit happens")
		}
	}

	return dwarf.VoidType{}
}