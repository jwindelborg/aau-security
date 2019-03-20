-- Hvilke domains laver flest cookies?
SELECT cookie_domain,
	COUNT(cookie_domain) AS Freq
    FROM cookies
    GROUP BY cookie_domain
    ORDER BY Freq DESC
    LIMIT 5;


SELECT *
    FROM cookies
    WHERE domain_id = 640085;



-- Hvilke domains har flest cookies?
SELECT domain, COUNT(c.domain_id)
    FROM domains
    JOIN cookies c on domains.domain_id = c.domain_id
    GROUP BY c.domain_id
    ORDER BY COUNT(c.domain_id) DESC;

-- Hyppigst inkluderede js url
SELECT `url`, COUNT(`url`) AS `value_occurrence`
FROM `javascriptdomains`
GROUP BY `url`
ORDER BY `value_occurrence` DESC
LIMIT 100;

-- Hvor mange cookies er secure?
SELECT SUM(is_secure) / COUNT(*) * 100 SecurePct
    FROM cookies;

-- Hvor mange cookies er http only?
SELECT SUM(is_http_only) / COUNT(*) * 100 HttpPct
    FROM cookies;

-- Hvor meget javascript er external?
SELECT SUM(is_external) / COUNT(*) * 100 extPct
    FROM javascriptdomains;

-- hvilke libraries har haft flest kendte vulnerabilities?
SELECT libname, COUNT(libname) AS freq
    FROM libraries
    JOIN libraryvulnerabilities ON libraries.library_id = libraryvulnerabilities.library_id
    GROUP BY libname
    ORDER BY freq DESC
    LIMIT 99;

-- hvilke libraries er skyld i flest vulnerable sider?
SELECT libname, COUNT(domains.domain_id) AS freq
    FROM libraries
    JOIN libraryvulnerabilities ON libraries.library_id = libraryvulnerabilities.library_id
    JOIN javascriptlibraries ON libraryvulnerabilities.library_id = javascriptlibraries.library_id
    JOIN javascriptdomains ON javascriptlibraries.js_url = javascriptdomains.url
    JOIN domains ON javascriptdomains.domain_id = domains.domain_id
    GROUP BY libname
    ORDER BY freq DESC
    LIMIT 5;


-- Hvilke libraryversioner har flest kendte vulnerabilities?
SELECT library_id,
	COUNT(library_id) AS freq
    FROM libraryvulnerabilities
    GROUP BY library_id
    ORDER BY freq DESC
    LIMIT 5; -- skal laves om så den viser library og versionsnummer i stedet for id

-- Hvilke domains benytter flest kendte vulnerabilities? (Tæller også vulns brugt flere gange)
SELECT domain, COUNT(domains.domain_id) AS freq
    FROM domains
    JOIN javascriptdomains on domains.domain_id = javascriptdomains.domain_id
    JOIN javascriptlibraries on javascriptdomains.url = javascriptlibraries.js_url
    JOIN libraryvulnerabilities on javascriptlibraries.library_id = libraryvulnerabilities.library_id
    GROUP BY domains.domain_id, domains.domain_id
    ORDER BY freq DESC
    LIMIT 5; -- ikke testet. kan først testes når de nye tabeller udfyldes

-- Hvilke domains har flest kendte unikke vulnerabilities?
SELECT domain, COUNT(DISTINCT libraryvulnerabilities.vulnerability_id) AS freq
    FROM domains
    JOIN javascriptdomains on domains.domain_id = javascriptdomains.domain_id
    JOIN javascriptlibraries on javascriptdomains.url = javascriptlibraries.js_url
    JOIN libraryvulnerabilities on javascriptlibraries.library_id = libraryvulnerabilities.library_id
    GROUP BY domains.domain_id, domains.domain_id
    ORDER BY freq DESC;

-- Hvilke kendte vulnerabilities er de mest hyppige?
SELECT vulnerability_id,
	COUNT(vulnerability_id) AS Freq
    FROM libraryvulnerabilities
    GROUP BY vulnerability_id
    ORDER BY Freq DESC
    LIMIT 5;

-- Hvilke sider har flest high eller værre vulnerabilities?
SELECT domain, SUM(CASE WHEN vulnerabilities.severity >= 3 THEN 1 ELSE 0 END) AS SevFreq
    FROM domains
    JOIN javascriptdomains on domains.domain_id = javascriptdomains.domain_id
    JOIN javascriptlibraries on javascriptdomains.url = javascriptlibraries.js_url
    JOIN libraryvulnerabilities on javascriptlibraries.library_id = libraryvulnerabilities.library_id
    JOIN vulnerabilities on libraryvulnerabilities.vulnerability_id = vulnerabilities.vulnerability_id
    GROUP BY domains.domain_id, vulnerabilities.severity
    ORDER BY SevFreq DESC
    LIMIT 5; -- ikke testet. kan først testes når de nye tabeller udfyldes

-- Hvilke libraries har vi fundet som ikke har vulnerabilities?
SELECT libname, version
    FROM libraries
    WHERE library_id NOT IN
      (SELECT library_id FROM libraryvulnerabilities);

-- Hvor mange procent har en eller anden form for vulnerability?
SELECT (COUNT(DISTINCT vulnerabledomains.domain) / (COUNT(domains.domain_id)-4222)) * 100 VulnPct
FROM vulnerabledomains, domains;

-- Hvor mange sider giver ingen data
SELECT domain
    FROM domains
    WHERE domain_id NOT IN
      (SELECT domain_id FROM javascriptdomains)
  AND domain_id NOT IN
      (SELECT domain_id FROM cookies)
  AND title = '';
