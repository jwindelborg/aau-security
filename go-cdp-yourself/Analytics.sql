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
SELECT js_url,
	COUNT(js_url) AS freq
    FROM javascriptvulnerabilities
    GROUP BY js_url
    ORDER BY freq DESC
    LIMIT 5;

-- Hvilke domains har flest kendte vulnerabilities?
SELECT domain, COUNT(domains.domain_id) AS freq
    FROM domains
    JOIN javascriptdomains on domains.domain_id = javascriptdomains.domain_id
    JOIN javascriptvulnerabilities on javascriptdomains.url = javascriptvulnerabilities.js_url
    GROUP BY domains.domain_id, domains.domain_id
    ORDER BY freq DESC
    LIMIT 5;

-- Hvilke kendte vulnerabilities er de mest hyppige?
SELECT vulnerability_id,
	COUNT(vulnerability_id) AS Freq
    FROM javascriptvulnerabilities
    GROUP BY vulnerability_id
    ORDER BY Freq DESC
    LIMIT 5;

-- Hvilke sider har flest critical vulnerabilities?
SELECT domain, SUM(CASE WHEN vulnerabilities.severity = 3 THEN 1 ELSE 0 END) AS SevFreq
    FROM domains
    JOIN javascriptdomains on domains.domain_id = javascriptdomains.domain_id
    JOIN javascriptvulnerabilities on javascriptdomains.url = javascriptvulnerabilities.js_url
    JOIN vulnerabilities on javascriptvulnerabilities.vulnerability_id = vulnerabilities.vulnerability_id
    GROUP BY domains.domain_id, vulnerabilities.severity
    ORDER BY SevFreq DESC
    LIMIT 5;

-- Hvor mange sider har vi ikke data for?
SELECT count(*)
FROM domains
WHERE domain_id NOT IN
      (SELECT domain_id FROM javascriptdomains)
  AND domain_id NOT IN
      (SELECT domain_id FROM cookies);