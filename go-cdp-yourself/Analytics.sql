-- Hvilke domains laver flest cookies?
SELECT cookie_domain,
	COUNT(cookie_domain) AS Freq
    FROM cookies
    GROUP BY cookie_domain
    ORDER BY Freq DESC
    LIMIT 5;

-- Hvilke domains har flest cookies?
SELECT domain, COUNT(c.domain_id)
    FROM domains
    JOIN cookies c on domains.domain_id = c.domain_id
    GROUP BY c.domain_id
    ORDER BY COUNT(c.domain_id) DESC;

-- Hvor mange cookies er secure?
SELECT SUM(is_secure) / COUNT(*) * 100 SecurePct
    FROM cookies;

-- Hvor mange cookies er http only?
SELECT SUM(is_http_only) / COUNT(*) * 100 HttpPct
    FROM cookies;

-- Hvor meget javascript er external?
SELECT SUM(is_external) / COUNT(*) * 100 extPct
    FROM javascriptdomains;

-- Hvilke libraries har flest kendte vulnerabilities?
SELECT library_id,
	COUNT(library_id) AS freq
    FROM libraryvulnerabilities
    GROUP BY library_id
    ORDER BY freq DESC
    LIMIT 5;

-- Hvilke domains har flest kendte vulnerabilities?
SELECT domain, COUNT(domains.domain_id) AS freq
    FROM domains
    JOIN javascriptdomains on domains.domain_id = javascriptdomains.domain_id
    JOIN javascriptlibraries on javascriptdomains.url = javascriptlibraries.js_url
    JOIN libraryvulnerabilities on javascriptlibraries.library_id = libraryvulnerabilities.library_id
    GROUP BY domains.domain_id, domains.domain_id
    ORDER BY freq DESC
    LIMIT 5; -- ikke testet. kan først testes når de nye tabeller udfyldes

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
SELECT libname
    FROM libraries
    WHERE library_id NOT IN
      (SELECT library_id FROM libraryvulnerabilities);

-- Hvor mange sider giver ingen data
SELECT domain
    FROM domains
    WHERE domain_id NOT IN
      (SELECT domain_id FROM javascriptdomains)
  AND domain_id NOT IN
      (SELECT domain_id FROM cookies);
