package main

import (
	"log"
	"net/http"
	"strings"
)

func runServer(options options) {

	http.HandleFunc("/TrackingCookie/", func(w http.ResponseWriter, r *http.Request) {
		privacyBadgerToDB(curDomID, 0, strings.TrimPrefix(r.URL.Path, "/TrackingCookie/"), options)

		_, err := w.Write([]byte("ok"))
		if err != nil { log.Print(err) }
	})

	http.HandleFunc("/BlockDomain/", func(w http.ResponseWriter, r *http.Request) {
		privacyBadgerToDB(curDomID, 1, strings.TrimPrefix(r.URL.Path, "/BlockDomain/"), options)

		_, err := w.Write([]byte("ok"))
		if err != nil { log.Print(err) }
	})

	http.HandleFunc("/OriginMultipleTrack/", func(w http.ResponseWriter, r *http.Request) {
		privacyBadgerToDB(curDomID, 1, strings.TrimPrefix(r.URL.Path, "/OriginMultipleTrack/"), options)

		_, err := w.Write([]byte("ok"))
		if err != nil { log.Print(err) }
	})

	http.HandleFunc("/TrackingCookieTooHigh/", func(w http.ResponseWriter, r *http.Request) {
		privacyBadgerToDB(curDomID, 0, strings.TrimPrefix(r.URL.Path, "/TrackingCookieTooHigh/"), options)

		_, err := w.Write([]byte("ok"))
		if err != nil { log.Print(err) }
	})


	http.HandleFunc("/blockSetCookie/", privacyBadgerBlockSetCookie)
	http.HandleFunc("/strike/", privacyBadgerStrike)
	http.HandleFunc("/", privacyBadgerDebug)

	if err := http.ListenAndServe(":9000", nil); err != nil {
		panic(err)
	}
}

func privacyBadgerDebug(w http.ResponseWriter, r *http.Request) {
	log.Print(r.URL.Path)

	_, err := w.Write([]byte("ok"))
	if err != nil {
		log.Print(err)
	}
}

func privacyBadgerBlockSetCookie(w http.ResponseWriter, r *http.Request) {
	log.Print(r.URL.Path)
	//privacyBadgerToDB(curDomID, 0, strings.TrimPrefix(r.URL.Path, "/blockSetCookie/"))

	_, err := w.Write([]byte("ok"))
	if err != nil { log.Print(err) }
}

func privacyBadgerStrike(w http.ResponseWriter, r *http.Request) {
	message := "Strike " + strings.TrimPrefix(r.URL.Path, "/strike/")
	log.Print(message) // TODO: Not implemented in DB yet

	_, err := w.Write([]byte("ok"))
	if err != nil {	log.Print(err) }
}