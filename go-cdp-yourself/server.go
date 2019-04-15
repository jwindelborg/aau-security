package main

import (
	"log"
	"net/http"
	"strings"
)

func runServer() {
	http.HandleFunc("/TrackingCookie/", privacyBadgerCookie)
	http.HandleFunc("/BlockDomain/", privacyBadgerDomain)
	http.HandleFunc("/OriginMultipleTrack/", privacyBadgerMultipleTrack)
	http.HandleFunc("/TrackingCookieTooHigh/", privacyBadgerCookieTooHigh)
	http.HandleFunc("/strike/", privacyBadgerStrike)


	if err := http.ListenAndServe(":9000", nil); err != nil {
		panic(err)
	}
}

func privacyBadgerCookie(w http.ResponseWriter, r *http.Request) {
	// TODO: Flag cookie
	message := r.URL.Path
	message = strings.TrimPrefix(message, "/TrackingCookie/")
	message = "Test cookie " + message

	log.Print(message)

	message = "ok"
	_, err := w.Write([]byte(message))
	if err != nil {
		log.Print(err)
	}
}

func privacyBadgerMultipleTrack(w http.ResponseWriter, r *http.Request) {
	message := r.URL.Path
	message = strings.TrimPrefix(message, "/OriginMultipleTrack/")
	message = "Test multiple " + message

	log.Print(message)

	message = "ok"
	_, err := w.Write([]byte(message))
	if err != nil {
		log.Print(err)
	}
}

func privacyBadgerDomain(w http.ResponseWriter, r *http.Request) {
	message := r.URL.Path
	message = strings.TrimPrefix(message, "/BlockDomain/")
	message = "Test domain " + message

	log.Print(message)

	message = "ok"
	_, err := w.Write([]byte(message))
	if err != nil {
		log.Print(err)
	}
}

func privacyBadgerCookieTooHigh(w http.ResponseWriter, r *http.Request) {
	// TODO: Flag cookie
	message := r.URL.Path
	message = strings.TrimPrefix(message, "/TrackingCookieTooHigh/")
	message = "Test too high " + message

	log.Print(message)

	message = "ok"
	_, err := w.Write([]byte(message))
	if err != nil {
		log.Print(err)
	}
}

func privacyBadgerStrike(w http.ResponseWriter, r *http.Request) {
	message := r.URL.Path
	message = strings.TrimPrefix(message, "/strike/")
	message = "Strike " + message

	log.Print(message)

	message = "ok"
	_, err := w.Write([]byte(message))
	if err != nil {
		log.Print(err)
	}
}