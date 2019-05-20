package main

import (
	"log"
	"net/http"
	"strings"
)

func runServer(options options) {
	http.HandleFunc("/TrackingCookie/", func(w http.ResponseWriter, r *http.Request) {
		privacyBadgerToDB(curDomID, 0, strings.TrimPrefix(r.URL.Path, "/TrackingCookie/"), options)
		writeOk(w)
	})

	http.HandleFunc("/TrackingCookieTooHigh/", func(w http.ResponseWriter, r *http.Request) {
		privacyBadgerToDB(curDomID, 0, strings.TrimPrefix(r.URL.Path, "/TrackingCookieTooHigh/"), options)
		writeOk(w)
	})

	http.HandleFunc("/BlockDomain/", func(w http.ResponseWriter, r *http.Request) {
		privacyBadgerToDB(curDomID, 1, strings.TrimPrefix(r.URL.Path, "/BlockDomain/"), options)
		writeOk(w)
	})

	http.HandleFunc("/OriginMultipleTrack/", func(w http.ResponseWriter, r *http.Request) {
		privacyBadgerToDB(curDomID, 1, strings.TrimPrefix(r.URL.Path, "/OriginMultipleTrack/"), options)
		writeOk(w)
	})

	http.HandleFunc("/blockSetCookie/", privacyBadgerBlockSetCookie)
	http.HandleFunc("/strike/", privacyBadgerStrike)
	http.HandleFunc("/", privacyBadgerDebug)

	if err := http.ListenAndServe(":9000", nil); err != nil {
		log.Print(err)
		log.Print("Could not start SRV, port probably already in use")
		return
	}
}

func privacyBadgerDebug(w http.ResponseWriter, r *http.Request) {
	log.Print(r.URL.Path)
	writeOk(w)
}

func privacyBadgerBlockSetCookie(w http.ResponseWriter, r *http.Request) {
	log.Print(r.URL.Path)
	//privacyBadgerToDB(curDomID, 0, strings.TrimPrefix(r.URL.Path, "/blockSetCookie/"))
	writeOk(w)
}

func privacyBadgerStrike(w http.ResponseWriter, r *http.Request) {
	message := "Strike " + strings.TrimPrefix(r.URL.Path, "/strike/")
	log.Print(message) // TODO: Not implemented in DB yet
	writeOk(w)
}

func writeOk(w http.ResponseWriter) {
	_, err := w.Write([]byte("ok"))
	if err != nil { log.Print(err) }
}