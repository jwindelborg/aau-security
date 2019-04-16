package main

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

type options struct {
	dbName string
	port   string
	worker string
	doScan bool
	doPB   bool
}
