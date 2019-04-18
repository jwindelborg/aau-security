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

	sqlJs := `INSERT IGNORE INTO javascripts (script, scriptHash, javascriptDiscovered) VALUES (?, ?, NOW());`
	_, err = db.Exec(sqlJs, script.script, script.hash)
	if err != nil {
		log.Printf("javaScriptToDB: Error inserting JS into DB for external script: " + script.hash)
		log.Print(err)
	}

	sqlJsRel := `INSERT IGNORE INTO javascriptdomains (domain_id, scriptHash, url, is_external, scan_label) VALUES (?, ?, ?, ?, ?);`
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

	s := `INSERT IGNORE INTO cookies (domain_id, cookie_name, cookie_value, cookie_domain, cookie_expire, is_secure, is_http_only, cookie_added, scan_label) VALUES (?, ?, ?, ?, ?, ?, ?, now(), ?);`
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

	stmt := `INSERT INTO domainvisithistory (domain_id, worker, time_processed, scan_label) SELECT domain_id, ?, NOW(), ? FROM lockeddomains WHERE worker = ?;`
	_, err = db.Exec(stmt, workerName, options.scanLabel, workerName)
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
		log.Fatal("domainVisitHistory: Could not close DB conn")
	}

	return dwarf.VoidType{}
}

func privacyBadgerToDB(topDomainID int, isRed int, domain string, options options) dwarf.VoidType {
	db, err := sql.Open("mysql", connString)
	if err != nil {
		log.Fatal(err)
	}

	s := `INSERT IGNORE INTO privacyBadger (domain_id, is_red, concerning, accessed, scan_label) VALUES (?, ?, ?, now(), ?);`
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