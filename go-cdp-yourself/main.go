package main

import (
	"context"
	"database/sql"
	"debug/dwarf"
	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/runner"
	_ "github.com/go-sql-driver/mysql"
	"io/ioutil"
	_ "io/ioutil"
	"log"
	"strings"
	"time"
)

func main() {

	var domains = loadDomains(`zonefile.txt`)
	var numDomains = len(domains)
	var err error

	db, err := sql.Open("mysql", "aau:2387AXumK52aeaSA@tcp(85.191.223.61:3306)/aau")
	if err != nil {
		log.Fatal(err)
	}

	// create context
	ctxt, cancel := context.WithCancel(context.Background())
	defer cancel()

	// create chrome instance
	c, err := chromedp.New(ctxt, chromedp.WithRunnerOptions(
		runner.ProxyServer("http://127.0.0.1:8080"),
		))
	if err != nil {
		log.Fatal(err)
	}

	for i := 0; i < numDomains - 1; i++ {
		domain := "http://" + domains[i]
		doDomain(ctxt, c, *db, domain)
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

func doDomain(ctxt context.Context,c *chromedp.CDP, db sql.DB, domain string) dwarf.VoidType {
	var err error
	var tasks chromedp.Tasks
	var title string

	tasks = append(tasks, chromedp.Tasks{
		chromedp.Navigate(domain),
		chromedp.Sleep(10*time.Second),
		chromedp.Stop(),

		chromedp.Title(&title),
	})

	err = c.Run(ctxt, chromedp.Tasks{tasks})
	if err != nil {
		log.Fatal(err)
	}

	insert, err := db.Query("INSERT INTO Sites (`url`, `title`) VALUES ('" + domain + "', '" + title + "')")
	if err != nil {
		log.Fatal(err)
	}
	err = insert.Close()
	if err != nil {
		log.Fatal(err)
	}

	return dwarf.VoidType{}
}

func loadDomains(filename string) []string  {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	lines := strings.Split(string(content), "\n")
	return lines
}