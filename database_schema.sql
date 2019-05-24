create schema aau collate utf8_general_ci;

create table cms_vulnerabilities
(
	vulnerability_id varchar(250) not null primary key,
	description text not null,
	created_at datetime null
);

create table domains
(
	domain_id int auto_increment primary key,
	domain varchar(128) not null,
	created_at timestamp default CURRENT_TIMESTAMP not null on update CURRENT_TIMESTAMP
);

create table cdp_visit_history
(
	history_id int auto_increment primary key,
	domain_id int null,
	worker varchar(253) null,
	created_at datetime null,
	scan_label varchar(250) null,
	constraint domain_id_foregin_key
		foreign key (domain_id) references domains (domain_id)
			on update cascade
);

create table cookies
(
	domain_id int not null,
	cookie_name varchar(200) not null,
	cookie_value text not null,
	cookie_domain varchar(256) not null,
	cookie_expire float not null,
	is_secure int not null,
	is_http_only int not null,
	created_at datetime null,
	scan_label varchar(255) not null,
	primary key (domain_id, cookie_name, cookie_domain, scan_label),
	constraint cookies_domain_id
		foreign key (domain_id) references domains (domain_id)
			on update cascade on delete cascade
);

create index domain_id
	on cookies (domain_id);

create table domain_has_cms_vulnerabilities
(
	domain_id int not null,
	vulnerability_id varchar(250) not null,
	created_at datetime null,
	primary key (domain_id, vulnerability_id),
	constraint domain_has_vulnerability_vulnerability
		foreign key (vulnerability_id) references cms_vulnerabilities (vulnerability_id)
			on update cascade on delete cascade,
	constraint domain_id_foregin
		foreign key (domain_id) references domains (domain_id)
			on update cascade on delete cascade
);

create table hsts_policies
(
	domain_id int not null primary key,
	policy varchar(250) null,
	created_at datetime null,
	constraint htst_domain_id
		foreign key (domain_id) references domains (domain_id)
			on update cascade on delete cascade
);

create table http_headers
(
	domain_id int not null,
	request_url varchar(1000) not null,
	scan_label varchar(50) not null,
	created_at datetime null,
	header text not null,
	primary key (domain_id, request_url, scan_label),
	constraint http_header_domain_id
		foreign key (domain_id) references domains (domain_id)
			on update cascade on delete cascade
);

create table identified_cms
(
	domain_id int not null primary key,
	cms_system varchar(250) null,
	created_at datetime null,
	constraint identified_cms_domain_id
		foreign key (domain_id) references domains (domain_id)
			on update cascade on delete cascade
);

create table javascript_vulnerabilities
(
	vulnerability_id varchar(512) not null primary key,
	vulnerability_description text not null,
	severity int not null,
	created_at datetime null
);

create table javascripts
(
	javascript_hash varchar(1000) not null primary key,
	script longtext not null,
	created_at datetime null
);

create table domain_has_javascripts
(
	domain_id int not null,
	javascript_hash varchar(800) not null,
	is_external int not null,
	url varchar(1000) null,
	scan_label varchar(100) not null,
	created_at datetime null,
	primary key (domain_id, javascript_hash, scan_label),
	constraint domain_has_javascript_domain_id
		foreign key (domain_id) references domains (domain_id)
			on update cascade on delete cascade,
	constraint domain_has_javascript_javascript
		foreign key (javascript_hash) references javascripts (javascript_hash)
			on update cascade on delete cascade
);

create table javascript_analyzes
(
	analyze_id int auto_increment primary key,
	javascript_hash varchar(1000) null,
	analytic_tool varchar(512) null,
	worker varchar(253) null,
	created_at datetime null,
	constraint javascript_analyzes_hash
		foreign key (javascript_hash) references javascripts (javascript_hash)
			on update cascade on delete cascade
);

create table libraries
(
	library_id varchar(60) not null primary key,
	library_name varchar(60) not null,
	library_version varchar(60) not null,
	created_at datetime null
);

create table javascript_is_library
(
	javascript_hash varchar(940) not null,
	library_id varchar(60) not null,
	created_at datetime null,
	primary key (javascript_hash, library_id),
	constraint javascript_is_library_hash
		foreign key (javascript_hash) references javascripts (javascript_hash)
			on update cascade on delete cascade,
	constraint javascript_is_library_library
		foreign key (library_id) references libraries (library_id)
			on update cascade on delete cascade
);

create table library_has_vulnerabilities
(
	library_id varchar(60) not null,
	vulnerability_id varchar(60) not null,
	created_at datetime null,
	primary key (library_id, vulnerability_id),
	constraint library_has_vulnerability_libid
		foreign key (library_id) references libraries (library_id)
			on update cascade on delete cascade,
	constraint library_has_vulnerability_vuln_id
		foreign key (vulnerability_id) references javascript_vulnerabilities (vulnerability_id)
			on update cascade on delete cascade
);

create table locked_domains
(
	domain_id int not null,
	worker varchar(253) null,
	created_at datetime null,
	scan_label varchar(100) not null,
	primary key (domain_id, scan_label),
	constraint locked_domains_domain_id
		foreign key (domain_id) references domains (domain_id)
			on update cascade on delete cascade
);

create table locked_ssl_scan
(
	domain_id int not null,
	worker varchar(250) not null,
	created_at datetime null,
	primary key (domain_id, worker),
	constraint locked_ssl_scan_domain_id
		foreign key (domain_id) references domains (domain_id)
			on update cascade on delete cascade
);

create table powered_by
(
	domain_id int not null primary key,
	x_powered_by varchar(250) null,
	created_at datetime null,
	constraint powered_by_domain_id
		foreign key (domain_id) references domains (domain_id)
			on update cascade on delete cascade
);

create table privacy_badger_actions
(
	domain_id int not null,
	is_red tinyint(1) not null,
	concerning varchar(256) not null,
	created_at datetime not null,
	scan_label varchar(100) not null,
	primary key (domain_id, is_red, concerning, scan_label),
	constraint privacy_badger_domain_id
		foreign key (domain_id) references domains (domain_id)
			on update cascade on delete cascade
);

create table server_software
(
	software_hash varchar(500) not null,
	domain_id int not null,
	software varchar(150) null,
	version varchar(150) null,
	created_at datetime null,
	primary key (software_hash, domain_id),
	constraint server_software_domain_id
		foreign key (domain_id) references domains (domain_id)
			on update cascade on delete cascade
);

create table server_vulnerabilities
(
	cve varchar(250) not null primary key,
	score decimal(3,1) null,
	cve_description text null,
	created_at datetime not null
);

create table server_software_has_server_vulnerabilities
(
	cve varchar(250) not null,
	software_hash varchar(250) not null,
	primary key (cve, software_hash),
	constraint server_software_has_server_vuln_software_hash
		foreign key (software_hash) references server_software (software_hash)
			on update cascade on delete cascade,
	constraint server_software_hash_vuln_vuln_id
		foreign key (cve) references server_vulnerabilities (cve)
			on update cascade on delete cascade
);

create table ssl_properties
(
	domain_id int null,
	protocols varchar(256) not null,
	elliptic_curves varchar(128) not null,
	keysize varchar(128) not null,
	has_heartbleed tinyint(1) not null,
	has_ticketbleed tinyint(1) not null,
	has_robot tinyint(1) not null,
	has_sec_ren tinyint(1) not null,
	has_sec_ci_ren tinyint(1) not null,
	has_crime_tls tinyint(1) null,
	has_breach tinyint(1) not null,
	has_poodle_ssl tinyint(1) not null,
	has_sweet32 tinyint(1) not null,
	has_freak tinyint(1) not null,
	has_drown tinyint(1) not null,
	has_logjam tinyint(1) not null,
	has_beast tinyint(1) null,
	has_lucky13 tinyint(1) not null,
	has_rc4 tinyint(1) not null,
	created_at datetime null,
	constraint ssl_properties_domain_id
		foreign key (domain_id) references domains (domain_id)
			on update cascade on delete cascade
);

create table ssl_scan_history
(
	history_id int auto_increment primary key,
	worker varchar(250) null,
	domain_id int null,
	created_at datetime null,
	constraint ssl_scan_history_domain_id
		foreign key (domain_id) references domains (domain_id)
			on update cascade on delete cascade
);
