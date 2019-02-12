package main

import (
	"context"
	"database/sql"
	"debug/dwarf"
	"encoding/hex"
	"github.com/anaskhan96/soup"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
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
	"strings"
	"time"
)

type Domain struct {
	domain string
	id int
}

type DomainCookie struct {
	name string
	domain string
	value string
	expires float64
	httponly int
	secure int
}

func main() {
	var err error

	ctxt, cancel := context.WithCancel(context.Background())
	defer cancel()

	domains := loadDomainsDB(ctxt)

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
		ctxDomain, cancelDomain := context.WithTimeout(context.Background(), 100*time.Second)
		doDomain(ctxDomain, c, domains[i])
		cancelDomain() // https://stackoverflow.com/questions/45617758/defer-in-the-loop-what-will-be-better
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
	db.SetConnMaxLifetime(66 * time.Second)
	if err != nil {
		log.Fatal(err)
	}


	// TODO: Find a way to access DevTools network tab
	tasks = append(tasks, chromedp.Tasks{
		network.ClearBrowserCookies(),
		network.ClearBrowserCache(),
		security.SetIgnoreCertificateErrors(true), // if intercept with burp or mitmproxy certificate is not signed
		// TODO: Find a way to access profiler data, it gives specific knowledge about run JavaScript
		profiler.Enable(),
		profiler.Start(),
		profiler.StartPreciseCoverage(),
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
					name:cookie.Name,
					domain:cookie.Domain,
					expires:cookie.Expires,
					httponly:boolToInt(cookie.HTTPOnly),
					secure:boolToInt(cookie.Secure),
					value:cookie.Value,

				}
				cookies = append(cookies, tmpCookie)
			}

			return nil
		}),
	})

	// Consider setting a flag between sites for mitmproxy

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

	for _, element := range cookies {
		sqlInsertCookie := `INSERT INTO cookie (domain_id, cookie_name, cookie_value, cookie_domain, cookie_expire, is_secure, is_http_only) VALUES (?, ?, ?, ?, ?, ?, ?);`
		_, err = db.Exec(sqlInsertCookie, domain.id, element.name, element.value, element.domain, element.expires, element.secure, element.httponly)
		if err != nil {
			log.Printf("Cookie already excists")
		}
	}

	htmldom := soup.HTMLParse(html)
	javascripts := htmldom.FindAll("script")
	for _, js := range javascripts {
		if js.Attrs()["src"] != "" {
			scriptURL := prepareScriptURL(domain.domain, js.Attrs()["src"])
			response, err := http.Get(scriptURL)
			if err != nil {
				log.Printf("Could not fetch script: " + scriptURL)
			}
			if response.StatusCode >= 200 && response.StatusCode < 400 {
				body, err := ioutil.ReadAll(response.Body)
				if err != nil {
					log.Printf("Could not fetch body for: " + scriptURL)
				} else {
					err := response.Body.Close()
					if err != nil {
						log.Printf("There was an error closing body for: " + scriptURL)
					}
					sqlJs := `INSERT INTO javascript (script, url) VALUES (?, ?);`
					_, err = db.Exec(sqlJs, string(body), scriptURL)
					if err != nil {
						log.Printf("10 Error inserting JS into DB for: " + scriptURL)
					}
					sqlJsRel := `INSERT INTO javascriptdomain (domain_id, url, is_external) VALUES (?, ?, ?);`
					_, err = db.Exec(sqlJsRel, domain.id, scriptURL, 1)
					if err != nil {
						log.Printf("20 Could not insert JS into DB for: " + scriptURL)
					}
				}

			}
		} else {
			shabytes := sha3.Sum256([]byte(js.Text()))
			sha := hex.EncodeToString(shabytes[:])
			sha = "/" + sha
			generatedUrl := prepareScriptURL(domain.domain, sha)
			sqlJs := `INSERT INTO javascript (script, url) VALUES (?, ?);`
			_, err = db.Exec(sqlJs, js.Text(), generatedUrl)
			if err != nil {
				log.Printf("30 Could not insert JS into DB for: " + generatedUrl)
			}
			sqlJsRel := `INSERT INTO javascriptdomain (domain_id, url, is_external) VALUES (?, ?, ?);`
			_, err = db.Exec(sqlJsRel, domain.id, generatedUrl, 0)
			if err != nil {
				log.Printf("40 Could not insert JS into DB for: " + generatedUrl)
			}
		}
	}

	err = db.Close()
	if err != nil {
		log.Fatal("Db conn could not be closed")
	}
	return dwarf.VoidType{}
}

func loadDomainsDB(ctxt context.Context) []Domain {
	db, err := sql.Open("mysql", "aau:2387AXumK52aeaSA@tcp(85.191.223.61:3306)/aau")
	db.SetMaxIdleConns(15) // TODO: This might not have any effect
	db.SetConnMaxLifetime(66 * time.Second) // TODO: This works, but why
	if err != nil {
		log.Fatal(err)
	}

	rows, err := db.QueryContext(ctxt, "SELECT domain_id, domain FROM domains WHERE domain_id ORDER BY RAND()")
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

	err = db.Close()
	if err != nil {
		log.Fatal("Could not close DB conn")
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

func boolToInt(bo bool) int {
	if bo {
		return 1
	} else {
		return 0
	}

}