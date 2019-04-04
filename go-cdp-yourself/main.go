package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"debug/dwarf"
	"encoding/hex"
	_ "github.com/go-sql-driver/mysql"
	"github.com/mafredri/cdp"
	"github.com/mafredri/cdp/devtool"
	"github.com/mafredri/cdp/protocol/dom"
	"github.com/mafredri/cdp/protocol/page"
	"github.com/mafredri/cdp/rpcc"
	"golang.org/x/crypto/sha3"
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

var connString = "aau:2387AXumK52aeaSA@tcp(142.93.109.128:3306)/"
var siteWorstCase = 80*time.Second
var queueReserved = 10

type Domain struct {
	domain string
	id     int
}

type DomainCookie struct {
	name     string
	domain   string
	value    string
	expires  float64
	httpOnly int
	secure   int
}

type JavaScript struct {
	script     string
	hash       string
	url        string
	isExternal bool
}

func main() {
	var dbName string
	channel := make(chan string)
	if len(os.Args) < 4 { // TODO: More input validation!
		err := "First parameter the DB\n Second parameter the port of the chromeDP (often 9222)\nThird parameter the worker name"
		log.Fatal(err)
	}
	if os.Args[1] == "--alexa" {
		dbName = "alexaDB"
	} else if os.Args[1] == "--dk" {
		dbName = "aau"
	} else if os.Args[1] == "--nidan" {
		dbName = "nidan"
	} else {
		err := "How about trying an argument that actually exists?"
		log.Fatal(err)
	}
	connString += dbName
	port := os.Args[2]
	workerName := os.Args[3]
	go startAndHandleChrome(port, channel)
	time.Sleep(1 * time.Second)
	finished := false

	for !finished {
		domains := loadDomainQueue(workerName)
		if len(domains) <= 0 {
			finished = true
			continue
		}
		for _, domain := range domains {
			log.Printf("Doing domain: " + domain.domain)
			doDomain(domain, port, channel)
		}
		domainVisitHistory(workerName)
	}
	log.Printf("No more domains to process!")
	channel <- "done"
}

func startAndHandleChrome(port string, channel chan string) {

	cmd := exec.Command("google-chrome-stable", "--headless", "--remote-debugging-port=" + port, "--disable-gpu")
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}

	for true {
		switch stmt := <-channel; stmt {
		case "fixed":
			time.Sleep(3 * time.Second)
			continue
		case "fix":
			// Kill it:
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

func doDomain(domain Domain, port string, channel chan string) dwarf.VoidType {

	checkChrome := false
	for !checkChrome {
		chromeUp, err := http.Get("http://127.0.0.1:" + port)
		if err != nil {
			channel <- "fix"
			log.Printf("Chrome not up, let's wait for a moment")
			log.Print(err)
			time.Sleep(10*time.Second)
			continue
		} else if chromeUp.StatusCode != 200 {
			channel <- "fix"
			log.Printf("Chrome not up, let's wait for status code 200")
			time.Sleep(10*time.Second)
			continue
		}
		checkChrome = true
	}

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
	defer conn.Close() // Leaving connections open will leak memory.

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

	// Create the Navigate arguments with the optional Referrer field set.
	navArgs := page.NewNavigateArgs("https://" + domain.domain)
	nav, err := c.Page.Navigate(ctx, navArgs)
	if err != nil {
		log.Print(err)
		return dwarf.VoidType{}
	}

	if _, err = domContent.Recv(); err != nil {
		log.Print(err)
		return dwarf.VoidType{}
	}

	if false { // I want to remember the option exists
		log.Printf("Page loaded with frame ID: %s\n", nav.FrameID)
	}

	// Fetch the document root node. We can pass nil here
	// since this method only takes optional arguments.
	doc, err := c.DOM.GetDocument(ctx, nil)
	if err != nil {
		log.Print(err)
		return dwarf.VoidType{}
	}

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
			javaScriptToDB(domain, theScript)
		} else {
			log.Printf("Hash not sat for JS; the script is probably not there")
		}

	}

	getAllCookies, err := cdp.Network.GetAllCookies(c.Network, ctx)
	if err != nil {
		log.Printf("Could not get cookies")
		log.Print(err)
	}

	cookiesLst := getAllCookies.Cookies
	for _, cookie := range cookiesLst {
		tmpCookie := DomainCookie {
			name:     cookie.Name,
			domain:   cookie.Domain,
			expires:  cookie.Expires,
			httpOnly: boolToInt(cookie.HTTPOnly),
			secure:   boolToInt(cookie.Secure),
			value:    cookie.Value,
		}
		cookieToDB(domain, tmpCookie)
	}

	return dwarf.VoidType{}
}

func javaScriptToDB(domain Domain, script JavaScript) dwarf.VoidType {
	db, err := sql.Open("mysql", connString)
	if err != nil {
		log.Fatal(err)
	}

	// JavaScript Save
	sqlJs := `INSERT IGNORE INTO javascripts (script, scriptHash, javascriptDiscovered) VALUES (?, ?, NOW());`
	_, err = db.Exec(sqlJs, script.script, script.hash)
	if err != nil {
		log.Printf("javaScriptToDB: Error inserting JS into DB for external script: " + script.hash)
		log.Print(err)
	}
	// JavaScript Domain save
	sqlJsRel := `INSERT IGNORE INTO javascriptdomains (domain_id, scriptHash, url, is_external) VALUES (?, ?, ?, ?);`
	_, err = db.Exec(sqlJsRel, domain.id, script.hash, script.url, script.isExternal)
	if err != nil {
		log.Printf("javaScriptToDB: Could not insert JS relation into DB for external script: " + script.hash)
		log.Print(err)
	}

	err = db.Close()
	if err != nil {
		log.Print(err)
		log.Fatal("javaScriptToDB: DB conn could not be closed")
	}
	return dwarf.VoidType{}
}

func cookieToDB(domain Domain, cookie DomainCookie) dwarf.VoidType {
	db, err := sql.Open("mysql", connString)
	if err != nil {
		log.Fatal(err)
	}

	sqlInsertCookie := `INSERT IGNORE INTO cookies (domain_id, cookie_name, cookie_value, cookie_domain, cookie_expire, is_secure, is_http_only, cookie_added) VALUES (?, ?, ?, ?, ?, ?, ?, now());`
	_, err = db.Exec(sqlInsertCookie, domain.id, cookie.name, cookie.value, cookie.domain, cookie.expires, cookie.secure, cookie.httpOnly)
	if err != nil {
		log.Printf("cookieToDB: Could not save cookie")
		log.Print(err)
	}

	err = db.Close()
	if err != nil {
		log.Print(err)
		log.Fatal("cookieToDB: db conn could not be closed")
	}

	return dwarf.VoidType{}
}

func loadDomainQueue(workerName string) []Domain {
	ctx, cancel := context.WithCancel(context.Background())

	db, err := sql.Open("mysql", connString)
	if err != nil {
		log.Fatal(err)
	}

	cleanstmt := `DELETE FROM lockeddomains WHERE worker = ?`
	_, err = db.Exec(cleanstmt, workerName)
	if err != nil {
		log.Printf("LoadDomainQueue: Could not delete from locked")
		log.Print(err)
	}

	lockstmt := `INSERT INTO lockeddomains (domain_id, worker, locked_time) SELECT domains.domain_id, ? AS 'worker', NOW() FROM domains WHERE domain_id NOT IN (SELECT domain_id FROM lockeddomains) AND domain_id NOT IN (SELECT domain_id FROM domainvisithistory) LIMIT ?;`
	_, err = db.Exec(lockstmt, workerName, queueReserved)
	if err != nil {
		log.Printf("LoadDomainQueue: Could not lock domains")
		log.Print(err)
	}

	rows, err := db.QueryContext(ctx, "SELECT domain_id, domain FROM domains WHERE domain_id IN (SELECT domain_id FROM lockeddomains WHERE worker = ?);", workerName)
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
		tmpDomain := Domain {
			id:     id,
			domain: strings.TrimSpace(domain),
		}

		domains = append(domains, tmpDomain)
	}
	err = rows.Close()
	if err != nil {
		log.Print(err)
		log.Fatal("LoadDomainsDB: Could not close rows")
	}
	err = db.Close()
	if err != nil {
		log.Print(err)
		log.Fatal("LoadDomainsDB: Could not close DB conn")
	}
	cancel()
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

func domainVisitHistory(workerName string) dwarf.VoidType {
	db, err := sql.Open("mysql", connString)
	if err != nil {
		log.Fatal(err)
	}

	stmt := `INSERT INTO domainvisithistory (domain_id, worker, time_processed) SELECT domain_id, ?, NOW() FROM lockeddomains WHERE worker = ?;`
	_, err = db.Exec(stmt, workerName, workerName)
	if err != nil {
		log.Printf("domainVisitHistory: Could not update history")
		log.Print(err)
	}
	stmt2 := `DELETE FROM lockeddomains WHERE worker = ?;`
	_, err = db.Exec(stmt2, workerName)
	if err != nil {
		log.Printf("domainVisitHistory: Could not delete locks")
		log.Print(err)
	}

	err = db.Close()
	if err != nil {
		log.Print(err)
		log.Fatal("LoadDomainsDB: Could not close DB conn")
	}

	return dwarf.VoidType{}
}

func putdomainstodb(filename string) dwarf.VoidType  {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	lines := strings.Split(string(content), "\n")

	db, err := sql.Open("mysql", connString)
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
