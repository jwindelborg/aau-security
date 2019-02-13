-- Hvilke domains laver flest cookies?
SELECT cookie_domain,
	COUNT(cookie_domain) AS freq
    FROM cookies
    GROUP BY cookie_domain
    ORDER BY freq DESC
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

-- Hvilke domains har flest kendte vulnerabilities?
SELECT javascript_checksum,
	COUNT(javascript_checksum) AS freq
    FROM javascriptvulnerabilities
    GROUP BY javascript_checksum
    ORDER BY freq DESC
    LIMIT 5;

-- Hvilke vulnerabilities er de mest hyppige?
SELECT vulnerability_id,
	COUNT(vulnerability_id) AS freq
    FROM javascriptvulnerabilities
    GROUP BY vulnerability_id
    ORDER BY freq DESC
    LIMIT 5;

-- Hvilke sider har flest critical vulnerabilities?
SELECT SUM(CASE WHEN severity = 4 THEN 1 ELSE 0 END) AS freq
    FROM vulnerabilities
    GROUP BY severity
    ORDER BY freq DESC
    LIMIT 5; -- IKKE TESTET!!!

-- Hvor mange sider har vi ikke data for?
SELECT count(*)
FROM domains
WHERE domain_id NOT IN
      (SELECT domain_id FROM javascriptdomains)
  AND domain_id NOT IN
      (SELECT domain_id FROM cookies);