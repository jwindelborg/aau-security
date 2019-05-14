# Our new database conventions

The rules described in this document takes precedence, antyhing not specified here follow (https://www.sqlstyle.guide/)[sqlstyle.guide]. In case of any doubt use common sense.

# Naming conventions

 * Database name is singular
 * Table names is plural
 * Columns are singular
 * Snakecase is used
 * All datatimes have the prefix `\_at`

If primary key is int auto increment use database name as singular `\_id`.

## Linking tables

 * Describe `has` or `is` relationship

## Timestamps

Use:
 * created\_at
 * updated\_at

Note: Created at means this record is created at, updated at means this record is updated at.

# Changes made

 * cmsvulnerabilities --> cms\_vulnerabilities
  - date\_added --> created\_at
 * cookies: created\_at
 * domains: created\_at
 * domain\_has\_cms\_vulnerabilities
 * domainsslscan -> ssl\_properties
  - created\_at
 * cdp\_visit\_history
  - created\_at
 * hsts\_policies
  - created\_at
 * http\_headers
  - created\_at
 * identified\_cms
  - created\_at
 * javascript\_analyzes
  - javascript\_hash
  - created\_at
 * javascriptdomains -> domain\_has\_javascripts
  - javascript\_hash
  - created\_at
 * javascriptlibraries -> javascript\_is\_library
  - javascript\_hash
  - created\_at
 * javascripts: javscript\_hash & created\_at
 * libraries: library\_name, library\_version, created\_at
 * libraryvulnerabilities -> library\_has\_vulnerabilities
  - created\_at
 * locked\_domains, created\_at
 * powered\_by
  - x\_powered\_by, created\_at
 * privacy\_badger\_actions
  - created\_at
 * server\_software
  - created\_at
 * serversoftwarevulnerabilities -> server\_software\_has\_server\_vulnerabilities
  - add domain\_id
  - new primary key (domain\_id, cve)
  - software -> software\_affected
 * servervulnerabilities -> server\_vulnerabilities
  - cve\_description, created\_at
 * ssllock -> locked\_ssl\_scan
  - created\_at
 * sslscanhistory -> ssl\_scan\_history
  - created\_at
 * vulnerabilities -> javascript\_vulnerabilities
  - created\_at, vulnerability -> vulnerability\_description
