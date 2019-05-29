package main

import (
	"database/sql"
	"debug/dwarf"
	"log"
)

func javaScriptToDB(domain Domain, script JavaScript, options options) dwarf.VoidType {
	db, err := sql.Open("mysql", connString)
	if err != nil {
		log.Fatal(err)
	}

	sqlJs := `INSERT IGNORE INTO javascripts (javascript_hash, script, created_at) VALUES (?, ?, NOW());`
	_, err = db.Exec(sqlJs, script.hash, script.script)
	if err != nil {
		log.Printf("javaScriptToDB: Error inserting JS into DB for external script: " + script.hash)
		log.Print(err)
	}

	sqlJsRel := `INSERT IGNORE INTO domain_has_javascripts (domain_id, javascript_hash, url, is_external, scan_label) VALUES (?, ?, ?, ?, ?);`
	_, err = db.Exec(sqlJsRel, domain.id, script.hash, script.url, script.isExternal, options.scanLabel)
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

func cookieToDB(domain Domain, cookie DomainCookie, options options) dwarf.VoidType {
	db, err := sql.Open("mysql", connString)
	if err != nil {
		log.Fatal(err)
	}

	s := `INSERT IGNORE INTO cookies (domain_id, cookie_name, cookie_value, cookie_domain, cookie_expire, is_secure, is_http_only, created_at, scan_label) VALUES (?, ?, ?, ?, ?, ?, ?, now(), ?);`
	_, err = db.Exec(s, domain.id, cookie.name, cookie.value, cookie.domain, cookie.expires, cookie.secure, cookie.httpOnly, options.scanLabel)
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

func domainVisitHistory(workerName string, options options) dwarf.VoidType {
	db, err := sql.Open("mysql", connString)
	if err != nil {
		log.Fatal(err)
	}

	stmt := `INSERT INTO cdp_visit_history (domain_id, worker, created_at, scan_label) SELECT domain_id, ?, NOW(), ? FROM locked_domains WHERE worker = ?;`
	_, err = db.Exec(stmt, workerName, options.scanLabel, workerName)
	if err != nil {
		log.Printf("domainVisitHistory: Could not update history")
		log.Print(err)
	}
	stmt2 := `DELETE FROM locked_domains WHERE worker = ?;`
	_, err = db.Exec(stmt2, workerName)
	if err != nil {
		log.Printf("domainVisitHistory: Could not delete locks")
		log.Print(err)
	}

	err = db.Close()
	if err != nil {
		log.Print(err)
		log.Fatal("domainVisitHistory: Could not close DB conn")
	}

	return dwarf.VoidType{}
}

func domainVisitedHistory(options options, domain Domain) dwarf.VoidType {
	db, err := sql.Open("mysql", connString)
	if err != nil {
		log.Fatal(err)
	}

	stmt := `INSERT INTO cdp_visit_history (domain_id, worker, created_at, scan_label) VALUES (?, ?, NOW(), ?)`
	_, err = db.Exec(stmt, domain.id, options.worker, options.scanLabel)
	if err != nil {
		log.Printf("domainVisitedHistory: Could not update history")
		log.Print(err)
		log.Fatal("Could not update history, lets die")
	}
	stmt2 := `DELETE FROM locked_domains WHERE domain_id = ?;`
	_, err = db.Exec(stmt2, domain.id)
	if err != nil {
		log.Printf("domainVisitedHistory: Could not delete lock")
		log.Print(err)
	}

	err = db.Close()
	if err != nil {
		log.Print(err)
		log.Fatal("domainVisitedHistory: Could not close DB conn")
	}

	return dwarf.VoidType{}
}

func privacyBadgerToDB(topDomainID int, isRed int, domain string, options options) dwarf.VoidType {
	db, err := sql.Open("mysql", connString)
	if err != nil {
		log.Fatal(err)
	}

	s := `INSERT IGNORE INTO privacy_badger_actions (domain_id, is_red, concerning, created_at, scan_label) VALUES (?, ?, ?, now(), ?);`
	_, err = db.Exec(s, topDomainID, isRed, domain, options.scanLabel)
	if err != nil {
		log.Printf("privacyBadgerToDB: Could not save Privacy Badger data")
		log.Print(err)
	}

	err = db.Close()
	if err != nil {
		log.Print(err)
		log.Fatal("privacyBadgerToDB: db conn could not be closed")
	}

	return dwarf.VoidType{}
}

func httpHeaderToDB(topDomainID int, url string, headers string, options options) dwarf.VoidType {
	db, err := sql.Open("mysql", connString)
	if err != nil {
		log.Fatal(err)
	}

	s := `INSERT IGNORE INTO http_headers (domain_id, request_url, scan_label, created_at, header) VALUES (?, ?, ?, now(), ?);`
	_, err = db.Exec(s, topDomainID, url, options.scanLabel, headers)
	if err != nil {
		log.Printf("httpHeaderToDB: Could not save HTTP header")
		log.Print(err)
	}

	err = db.Close()
	if err != nil {
		log.Print(err)
		log.Fatal("httpHeaderToDB: db conn could not be closed")
	}

	return dwarf.VoidType{}
}