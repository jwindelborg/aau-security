# Our new database conventions

The rules described in this document takes precedence, antyhing not specified here follow [https://www.sqlstyle.guide/](sqlstyle.guide). In case of any doubt use common sense.

# Naming conventions

 * Database name is singular
 * Table names is plural
 * Columns are singular
 * Snakecase is used
 * All datatimes have the prefix `_at`

If primary key is int auto increment use database name as singular `_id`.

## Linking tables

 * Describe `has` or `is` relationship

## Timestamps

Use:
 * created_at
 * updated_at

Note: Created at means this record is created at, updated at means this record is updated at.

# Changes made

 * cmsvulnerabilities --> cms_vulnerabilities
   - date_added --> created_at
 * cookies: created_at
 * domains: created_at
 * domain_has_cms_vulnerabilities
 * domainsslscan -> ssl_properties
   - created_at
 * cdp_visit_history
   - created_at
 * hsts_policies
   - created_at
 * http_headers
   - created_at
 * identified_cms
   - created_at
 * javascript_analyzes
   - javascript_hash
   - created_at
 * javascriptdomains -> domain_has_javascripts
   - javascript_hash
   - created_at
 * javascriptlibraries -> javascript_is_library
   - javascript_hash
   - created_at
 * javascripts: javscript_hash & created_at
 * libraries: library_name, library_version, created_at
 * libraryvulnerabilities -> library_has_vulnerabilities
   - created_at
 * locked_domains, created_at
 * powered_by
   - x_powered_by, created_at
 * privacy_badger_actions
   - created_at
 * server_software
   - created_at
 * serversoftwarevulnerabilities -> server_software_has_server_vulnerabilities
   - add domain_id
   - new primary key (domain_id, cve)
   - software -> software_affected
 * servervulnerabilities -> server_vulnerabilities
   - cve_description, created_at
 * ssllock -> locked_ssl_scan
   - created_at
 * sslscanhistory -> ssl_scan_history
   - created_at
 * vulnerabilities -> javascript_vulnerabilities
   - created_at, vulnerability -> vulnerability_description
