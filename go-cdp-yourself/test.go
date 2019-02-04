// Command pool is a chromedp example demonstrating how to use chromedp pool.
package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

func main() {
	var err error
	//var domains = loadDomains(`zonefile.txt`)

	// create context
	ctxt, cancel := context.WithCancel(context.Background())
	defer cancel()

	// create pool
	pool, err := chromedp.NewPool( chromedp.PoolLog(log.Printf, log.Printf, log.Printf) )
	if err != nil {
		log.Fatal(err)
	}

	// loop over the URLs
	var wg sync.WaitGroup
	for i, urlstr := range []string{
		"https://www.aau.dk/",
		"https://brank.as/careers",
		"https://brank.as/about",
		"https://ditonlinebetalingssystem.dk",
	} {
		wg.Add(1)
		go takeScreenshot(ctxt, &wg, pool, i, urlstr)
	}

	//wg.Add(len(domains)-1)
	//for i := 0; i < len(domains) - 1; i++ {
	//	var urlstr = "http://" + domains[i]
	//	go takeScreenshot(ctxt, &wg, pool, i, urlstr)
	//	//domain := "https://" + domains[i]
	//	//doDomain(ctxt, c, *db, domain)
	//}

	// wait for to finish
	wg.Wait()

	// shutdown pool
	err = pool.Shutdown()
	if err != nil {
		log.Fatal(err)
	}
}

func takeScreenshot(ctxt context.Context, wg *sync.WaitGroup, pool *chromedp.Pool, id int, urlstr string) {
	defer wg.Done()

	// allocate
	c, err := pool.Allocate(ctxt)
	if err != nil {
		log.Printf("url (%d) `%s` error: %v", id, urlstr, err)
		return
	}
	defer c.Release()

	// run tasks
	var buf []byte
	err = c.Run(ctxt, screenshot(urlstr, &buf))
	if err != nil {
		log.Printf("url (%d) `%s` error: %v", id, urlstr, err)
		return
	}

	// write to disk
	err = ioutil.WriteFile(fmt.Sprintf("%d.png", id), buf, 0644)
	if err != nil {
		log.Printf("url (%d) `%s` error: %v", id, urlstr, err)
		return
	}
}

func screenshot(urlstr string, picbuf *[]byte) chromedp.Action {
	return chromedp.Tasks{
		chromedp.Navigate(urlstr),
		chromedp.Sleep(30 * time.Second),
		//chromedp.WaitVisible(`#navbar-nav-main`),

		chromedp.ActionFunc(func(ctxt context.Context, h cdp.Executor) error {
			buf, err := page.CaptureScreenshot().Do(ctxt, h)
			if err != nil {
				return err
			}
			*picbuf = buf
			return nil
		}),
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