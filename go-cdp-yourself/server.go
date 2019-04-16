package main

import (
	"log"
	"net/http"
	"strings"
)

func runServer(opt options) {
	http.HandleFunc("/TrackingCookie/", privacyBadgerCookie)
	http.HandleFunc("/BlockDomain/", privacyBadgerDomain)
	http.HandleFunc("/blockSetCookie/", privacyBadgerBlockSetCookie)
	http.HandleFunc("/OriginMultipleTrack/", privacyBadgerMultipleTrack)
	http.HandleFunc("/TrackingCookieTooHigh/", privacyBadgerCookieTooHigh)
	http.HandleFunc("/strike/", privacyBadgerStrike)
	if !opt.quite {
		http.HandleFunc("/", privacyBadgerDebug)
	}

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

func privacyBadgerCookie(w http.ResponseWriter, r *http.Request) {
	// TODO: Flag cookie
	privacyBadgerToDB(curDomID, 0, strings.TrimPrefix(r.URL.Path, "/TrackingCookie/"))

	_, err := w.Write([]byte("ok"))
	if err != nil {
		log.Print(err)
	}
}

func privacyBadgerBlockSetCookie(w http.ResponseWriter, r *http.Request) {
	log.Print(r.URL.Path)
	// TODO: Flag cookie
	//privacyBadgerToDB(curDomID, 0, strings.TrimPrefix(r.URL.Path, "/blockSetCookie/"))

	_, err := w.Write([]byte("ok"))
	if err != nil {
		log.Print(err)
	}
}

func privacyBadgerMultipleTrack(w http.ResponseWriter, r *http.Request) {
	privacyBadgerToDB(curDomID, 1, strings.TrimPrefix(r.URL.Path, "/OriginMultipleTrack/"))

	_, err := w.Write([]byte("ok"))
	if err != nil {
		log.Print(err)
	}
}

func privacyBadgerDomain(w http.ResponseWriter, r *http.Request) {
	privacyBadgerToDB(curDomID, 1, strings.TrimPrefix(r.URL.Path, "/BlockDomain/"))

	_, err := w.Write([]byte("ok"))
	if err != nil {
		log.Print(err)
	}
}

func privacyBadgerCookieTooHigh(w http.ResponseWriter, r *http.Request) {
	// TODO: Flag cookie
	privacyBadgerToDB(curDomID, 0, strings.TrimPrefix(r.URL.Path, "/TrackingCookieTooHigh/"))

	_, err := w.Write([]byte("ok"))
	if err != nil {
		log.Print(err)
	}
}

func privacyBadgerStrike(w http.ResponseWriter, r *http.Request) {
	message := "Strike " + strings.TrimPrefix(r.URL.Path, "/strike/")

	log.Print(message) // TODO: Not implemented in DB yet

	_, err := w.Write([]byte("ok"))
	if err != nil {
		log.Print(err)
	}
}