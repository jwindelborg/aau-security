-- Hvilke domains laver flest cookies?
SELECT cookie_domain, 
	COUNT(cookie_domain) AS freq 
    FROM cookie
    GROUP BY cookie_domain
    ORDER BY freq DESC
    LIMIT 5;

-- Hvilke domains har flest cookies?
SELECT domain, COUNT(c.domain_id)
    FROM domains
    JOIN cookie c on domains.domain_id = c.domain_id
    GROUP BY c.domain_id
    ORDER BY COUNT(c.domain_id) DESC

-- Hvor mange cookies er secure?
SELECT SUM(is_secure) / COUNT(*) * 100 SecurePct 
    FROM cookie

-- Hvor mange cookies er http only?
SELECT SUM(is_http_only) / COUNT(*) * 100 HttpPct 
    FROM cookie

-- Hvor meget javascript er external?
SELECT SUM(is_external) / COUNT(*) * 100 extPct 
    FROM javascriptdomain

-- Hvilke domains har flest vulnerabilities?
SELECT javascript_checksum, 
	COUNT(javasscript_checksum) AS freq 
    FROM javascriptvulnerability
    GROUP BY javascript_checksum
    ORDER BY freq DESC
    LIMIT 5;

-- Hvilke vulnerabilities er de mest hyppige?
SELECT vulnerability_id,
	COUNT(vulnerability_id) AS freq 
    FROM javascriptvulnerability
    GROUP BY vulnerability_id
    ORDER BY freq DESC
    LIMIT 5;

