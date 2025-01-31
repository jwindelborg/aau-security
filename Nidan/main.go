package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"debug/dwarf"
	_ "github.com/go-sql-driver/mysql"
	"github.com/mafredri/cdp"
	"github.com/mafredri/cdp/devtool"
	"github.com/mafredri/cdp/protocol/dom"
	"github.com/mafredri/cdp/protocol/page"
	"github.com/mafredri/cdp/rpcc"
	_ "golang.org/x/crypto/sha3"
	"io/ioutil"
	_ "io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

var connString = configurationParser()
var siteWorstCase = 100*time.Second
var curDomID = 0

func main() {
	channel := make(chan string)

	options := argParse(os.Args)

	go startAndHandleChrome(channel, options)
	time.Sleep(5 * time.Second)
	finished := false

	if options.doPB {
		go runServer(options)
	}

	for !finished {
		domains := loadDomainQueue(options)
		if len(domains) <= 0 {
			finished = true
			continue
		}
		for _, domain := range domains {
			if !options.quite { log.Printf("Doing domain: " + domain.domain) }
			curDomID = domain.id
			doDomain(domain, options.port, channel, options)
		}
	}
	log.Printf("No more domains to process!")
	channel <- "done"
}

func startAndHandleChrome(channel chan string, options options) {

	// xvfb-run chromium --load-extension=~/privacybadger/src/ --remote-debugging-port=9222 --disable-gpu
	cmd := exec.Command(
		//"xvfb-run", // X Virtual Framebuffer, used for Privacy Badger
		options.chromeName,
		//"--load-extension=~/privacybadger/src/",
		"--remote-debugging-port=" + options.port,
		"--disable-gpu",
		"--headless",
		"--no-sandbox", // Required to run as root
		)
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
	log.Print("Chrome started")

	for true {
		switch stmt := <-channel; stmt {
		case "fixed":
			time.Sleep(3 * time.Second)
			continue
		case "fix":
			err := cmd.Process.Signal(syscall.SIGTERM)
			if err != nil {
				log.Fatal("failed to kill process: ", err)
			}
			_, err = cmd.Process.Wait()
			if err != nil {
				log.Fatal(err)
			}

			if err := cmd.Start(); err != nil {
				log.Print(err)
			}
			channel <- "fixed"
		case "done":
			err := cmd.Process.Signal(syscall.SIGTERM)
			if err != nil {
				log.Fatal("failed to kill process: ", err)
			}
			_, err = cmd.Process.Wait()
			if err != nil {
				log.Fatal(err)
			}
		default:
			log.Fatal("Unknown channel")
		}
		time.Sleep(3 * time.Second)
	}

}

func doDomain(domain Domain, port string, channel chan string, options options) dwarf.VoidType {

	checkChrome := false
	for !checkChrome {
		chromeUp, err := http.Get("http://127.0.0.1:" + port)
		if err != nil {
			channel <- "fix"
			log.Print(err)
			log.Fatal("Chrome instance died. Killing instance.")
		} else if chromeUp.StatusCode != 200 {
			channel <- "fix"
			log.Printf("Chrome is not running, Waiting for status code 200")
			time.Sleep(10*time.Second)
			continue
		}
		checkChrome = true
	}

	if options.doScan {
		domainVisitedHistory(options, domain)
	}

	//region Chrome setup
	ctx, cancel := context.WithTimeout(context.Background(), siteWorstCase)
	defer cancel()

	devTools := devtool.New("http://127.0.0.1:" + port)
	pt, err := devTools.Get(ctx, devtool.Page)
	if err != nil {
		pt, err = devTools.Create(ctx)
		if err != nil {
			log.Print(err)
			return dwarf.VoidType{}
		}
	}

	conn, err := rpcc.DialContext(ctx, pt.WebSocketDebuggerURL)
	if err != nil {
		log.Print(err)
		return dwarf.VoidType{}
	}
	defer conn.Close()

	c := cdp.NewClient(conn)

	// Open a DOMContentEventFired client to buffer this event.
	domContent, err := c.Page.DOMContentEventFired(ctx)
	if err != nil {
		log.Print(err)
		return dwarf.VoidType{}
	}
	defer domContent.Close()

	// Enable events on the Page domain, it's often preferable to create
	// event clients before enabling events so that we don't miss any.
	if err = c.Page.Enable(ctx); err != nil {
		log.Print(err)
		return dwarf.VoidType{}
	}

	// Clean up
	err = c.Network.ClearBrowserCache(ctx)
	if err != nil {
		log.Print(err)
	}
	err = c.Network.ClearBrowserCookies(ctx)
	if err != nil {
		log.Print(err)
	}
	//endregion Chrome setup

	// Create the Navigate arguments with the optional Referrer field set.
	navArgs := page.NewNavigateArgs("http://" + domain.domain)
	_, err = c.Page.Navigate(ctx, navArgs)
	if err != nil {
		log.Print(err)
		return dwarf.VoidType{}
	}

	if _, err = domContent.Recv(); err != nil {
		log.Print(err)
		return dwarf.VoidType{}
	}

	// Fetch the document root node. We can pass nil here
	// since this method only takes optional arguments.
	doc, err := c.DOM.GetDocument(ctx, nil)
	if err != nil {
		log.Print(err)
		return dwarf.VoidType{}
	}

	httpHeaders := getHttpHeaders(*doc.Root.BaseURL)
	if httpHeaders != "" {
		httpHeaderToDB(curDomID, *doc.Root.BaseURL, httpHeaders, options)
	}

	// Handle JavaScript
	if options.doScan {
		scriptIDs, err := c.DOM.QuerySelectorAll(ctx, dom.NewQuerySelectorAllArgs(doc.Root.NodeID, "script"))
		if err != nil {
			log.Println(err)
			return dwarf.VoidType{}
		}

		for _, script := range scriptIDs.NodeIDs {
			var theScript JavaScript
			externalFlag := false
			getOutPar := dom.GetOuterHTMLArgs{
				NodeID:&script,
			}
			getAttrPar := dom.GetAttributesArgs{
				NodeID:script,
			}
			outer, _ := c.DOM.GetOuterHTML(ctx, &getOutPar)
			attr, _ := c.DOM.GetAttributes(ctx, &getAttrPar)
			for i, atr := range attr.Attributes {
				if atr == "src" {
					externalFlag = true
					scriptURL := prepareScriptURL(domain.domain,attr.Attributes[i+1])
					http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
					response, err := http.Get(scriptURL)
					if err != nil {
						log.Printf("doDomain: Could not fetch external script: " + scriptURL)
						log.Print(err)
						continue
					}
					if response.StatusCode >= 200 && response.StatusCode < 400 {
						body, err := ioutil.ReadAll(response.Body)
						if err != nil {
							log.Printf("doDomain: Could not get response body for external script: " + scriptURL)
							log.Print(err)
							continue
						} else {
							err := response.Body.Close()
							if err != nil {
								log.Printf("doDomain: There was an error closing body for external script: " + scriptURL)
								log.Print(err)
								continue
							}
							theScript.script = string(body)
							theScript.hash = sha3FromStr(string(body))
							theScript.url = scriptURL
							theScript.isExternal = true
						}
					}
				}
			}
			if !externalFlag {
				if outer != nil {
					startIndex := strings.Index(outer.OuterHTML, ">") + 1
					endIndex := strings.LastIndex(outer.OuterHTML, "</script>")
					if startIndex != -1 && endIndex != -1 {
						theScript.script = outer.OuterHTML[startIndex:endIndex]
					} else {
						theScript.script = outer.OuterHTML
					}
					theScript.hash = sha3FromStr(theScript.script)
					theScript.isExternal = false
					theScript.url = domain.domain
				}
			}
			if theScript.hash != "" {
				javaScriptToDB(domain, theScript, options)
			} else {
				log.Printf("Hash not sat for JS; the script is probably not there")
			}
		}
	}

	// Handle Cookies
	if options.doScan {
		getAllCookies, err := cdp.Network.GetAllCookies(c.Network, ctx)
		if err != nil {
			log.Printf("Could not get cookies")
			log.Print(err)
		}

		cookiesLst := getAllCookies.Cookies
		for _, cookie := range cookiesLst {
			cookieToDB(domain, DomainCookie{
				name:     cookie.Name,
				domain:   cookie.Domain,
				expires:  cookie.Expires,
				httpOnly: boolToInt(cookie.HTTPOnly),
				secure:   boolToInt(cookie.Secure),
				value:    cookie.Value,
			}, options)
		}
	}

	return dwarf.VoidType{}
}

func loadDomainQueue(options options) []Domain {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db, err := sql.Open("mysql", connString)
	if err != nil {
		log.Fatal(err)
	}

	cleanStmt := `DELETE FROM locked_domains WHERE worker = ?`
	_, err = db.Exec(cleanStmt, options.worker)
	if err != nil {
		log.Printf("loadDomainQueue: Could not delete from locked")
		log.Print(err)
	}

	var lockStmt string
	if options.scanOld {
		lockStmt = `INSERT INTO locked_domains (domain_id, worker, created_at, scan_label) 
					SELECT domains.domain_id, ? AS 'worker', NOW(), ? 
					FROM domains WHERE domain_id NOT IN (
					    SELECT domain_id FROM locked_domains WHERE scan_label = ?)`
		if options.random { lockStmt += ` ORDER BY rand() LIMIT ?;`	} else { lockStmt += ` LIMIT ?;` }
		_, err = db.Exec(lockStmt, options.worker, options.scanLabel, options.scanLabel, options.queueSize)
	} else {
		lockStmt = `INSERT INTO locked_domains (domain_id, worker, created_at, scan_label) 
					SELECT domains.domain_id, ? AS 'worker', NOW(), ? 
					FROM domains WHERE domain_id NOT IN 
					                   (SELECT domain_id 
					                   FROM locked_domains 
					                   WHERE scan_label = ?) 
					               AND domain_id NOT IN 
					                   (SELECT domain_id FROM cdp_visit_history WHERE scan_label = ?)`
		if options.random { lockStmt += ` ORDER BY rand() LIMIT ?;`	} else { lockStmt += ` LIMIT ?;` }
		_, err = db.Exec(lockStmt, options.worker, options.scanLabel, options.scanLabel, options.scanLabel, options.queueSize)
	}

	if err != nil {
		log.Printf("loadDomainQueue: Could not lock domains")
		log.Print(err)
		log.Fatal("No domains locked lets die")
	}

	rows, err := db.QueryContext(ctx, "SELECT domain_id, domain FROM domains WHERE domain_id IN (SELECT domain_id FROM locked_domains WHERE worker = ?);", options.worker)
	if err != nil {
		log.Fatal(err)
	}

	var domains []Domain

	for rows.Next() {
		var (
			id     int
			domain string
		)
		if err := rows.Scan(&id, &domain); err != nil {
			log.Fatal(err)
		}

		domains = append(domains, Domain{
			id:     id,
			domain: strings.TrimSpace(domain),
		})
	}
	err = rows.Close()
	if err != nil {
		log.Print(err)
		log.Fatal("loadDomainQueue: Could not close rows")
	}
	err = db.Close()
	if err != nil {
		log.Print(err)
		log.Fatal("loadDomainQueue: Could not close DB connection")
	}
	return domains
}
