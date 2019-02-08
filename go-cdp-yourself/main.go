package main

// Before use
// docker run -d -p 9222:9222 --rm --name headless-shell chromedp/headless-shell
//

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
	"regexp"
	"strings"
	"time"
)

type Domain struct {
	domain string
	id int
}

func main() {

	//var domains = loadDomains(`zonefile.txt`)

	var err error

	db, err := sql.Open("mysql", "aau:2387AXumK52aeaSA@tcp(85.191.223.61:3306)/aau")
	if err != nil {
		log.Fatal(err)
	}

	// create context
	ctxt, cancel := context.WithCancel(context.Background())
	defer cancel()

	var domains = loadDomainsDB(ctxt, *db)
	var numDomains = len(domains)

	// create chrome instance
	c, err := chromedp.New(ctxt,
		chromedp.WithRunnerOptions(
			//runner.ProxyServer("http://127.0.0.1:8080"), // enable for mitmproxy or Burp
			runner.Flag("headless", true),
			runner.Flag("no-sandbox", true),
		),
		//chromedp.WithLog(log.Printf),
	)

	if err != nil {
		log.Fatal(err)
	}

	for i := 0; i < numDomains - 1; i++ {
		doDomain(ctxt, c, *db, domains[i])
	}

	// shutdown chrome
	err = c.Shutdown(ctxt)
	if err != nil {
		log.Fatal(err)
	}

	// wait for chrome to finish
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

	tasks = append(tasks, chromedp.Tasks{
		security.SetIgnoreCertificateErrors(true),
		profiler.Enable(),
		profiler.Start(),
		profiler.StartPreciseCoverage(),
		chromedp.Navigate("http://" + domain.domain),
		chromedp.Sleep(10*time.Second),
		chromedp.Stop(),
		chromedp.Title(&title),
		chromedp.EvaluateAsDevTools("var scri = []; for (var index = 0; index < document.getElementsByTagName('script').length; index++) { scri[index] = (document.getElementsByTagName('script')[index].outerHTML.toString()); }; btoa(scri.join('::,,//'));", &resJSbase64),
	})

	err = c.Run(ctxt, chromedp.Tasks{tasks})
	if err != nil {
		log.Fatal(err)
	}

	sqlStmt := `UPDATE domains SET title = ? WHERE domain_id = ?;`
	_, err = db.Exec(sqlStmt, title, domain.id)
	if err != nil {
		log.Fatal(err)
	}

	resJSbase64Decoded, err := base64.StdEncoding.DecodeString(resJSbase64)
	if err != nil {
		log.Fatal(err)
	}
	scripts := strings.Split(string(resJSbase64Decoded),"::,,//")

	for _, element := range scripts {
		var findScriptRegex = regexp.MustCompile(`<script\s+[^>]*?src=(("|')([^"']+))`)

		if !findScriptRegex.MatchString(element) {
			shabytes := sha3.Sum256([]byte(element))
			sha := hex.EncodeToString(shabytes[:])
			sqlJavaScriptInsert := `INSERT INTO javascript (script, javascript_checksum) VALUES (?, ?);`
			_, err = db.Exec(sqlJavaScriptInsert, element, sha)
			sqlJavaScriptRelationInsert := `INSERT INTO javascriptdomain (javascript_checksum, domain_id) VALUES (?, ?);`
			_, err = db.Exec(sqlJavaScriptRelationInsert, sha, domain.id)
		} //else {

			// Handled by mitmproxy
			// TODO: Handle this by mitmproxy

			//var scriptURL = findScriptRegex.FindStringSubmatch(element)[3]
			//
			//if scriptURL != "" {
			//	response, err := http.Get(scriptURL)
			//	body, err := ioutil.ReadAll(response.Body)
			//	if err != nil {
			//		//log.Fatal(err)
			//		log.Printf("not a valid url")
			//	} else {
			//		defer response.Body.Close()
			//	}
			//	element = string(body)
			//}
		//}
	}

	return dwarf.VoidType{}
}

func loadDomainsDB(ctxt context.Context, db sql.DB) []Domain {
	rows, err := db.QueryContext(ctxt, "SELECT domain_id, domain FROM domains")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var domains = []Domain{}

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
			domain: domain,
		}
		domains = append(domains, tmpDom)
	}

	return domains
}

func loadDomains(filename string) []string  {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	lines := strings.Split(string(content), "\n")
	return lines
}