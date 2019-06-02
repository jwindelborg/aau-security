-- Which third-party domains set the highest amount of cookies?
SELECT cookie_domain,
	COUNT(cookie_domain) AS Freq
    FROM cookies
    GROUP BY cookie_domain
    ORDER BY Freq DESC
    LIMIT 5;

-- Which domains has the highest amount of cookies?
SELECT domain, COUNT(c.domain_id)
    FROM domains
    JOIN cookies c on domains.domain_id = c.domain_id
    GROUP BY c.domain_id
    ORDER BY COUNT(c.domain_id) DESC;

-- Most frequently included JavaScript URL
SELECT `url`, COUNT(`url`) AS `value_occurrence`
FROM `domain_has_javascripts`
GROUP BY `url`
ORDER BY `value_occurrence` DESC
LIMIT 100;

-- Percentage of secure cookies
SELECT SUM(is_secure) / COUNT(*) * 100 SecurePct
    FROM cookies;

-- Percentage of http only cookies
SELECT SUM(is_http_only) / COUNT(*) * 100 HttpPct
    FROM cookies;

-- Percentage of external JavaScript
SELECT SUM(is_external) / COUNT(*) * 100 extPct
    FROM domain_has_javascripts;

-- Which libraries have had the highest amount of vulnerabilities?
SELECT libraries.library_id, COUNT(libraries.library_id) AS freq
    FROM libraries
    JOIN library_has_vulnerabilities ON libraries.library_id = library_has_vulnerabilities.library_id
    GROUP BY libraries.library_id
    ORDER BY freq DESC
    LIMIT 99;

-- Which libraries have caused the highest amount of vulnerable websites?
SELECT libraries.library_id, COUNT(domains.domain_id) AS freq
    FROM libraries
    JOIN library_has_vulnerabilities ON libraries.library_id = library_has_vulnerabilities.library_id
    JOIN javascript_is_library ON library_has_vulnerabilities.library_id = javascript_is_library.library_id
    JOIN domain_has_javascripts ON javascript_is_library.javascript_hash = domain_has_javascripts.javascript_hash
    JOIN domains ON domain_has_javascripts.domain_id = domains.domain_id
    GROUP BY libraries.library_id
    ORDER BY freq DESC
    LIMIT 5;

-- Which library versions have the highest amount of vulnerabilities?
SELECT libraries.libname, libraries.version, COUNT(library_has_vulnerabilities.library_id) AS freq
    FROM libraries
    JOIN library_has_vulnerabilities ON libraries.library_id = library_has_vulnerabilities.library_id
    GROUP BY library_has_vulnerabilities.library_id
    ORDER BY freq DESC;

-- Which domains has the highest amount of unique vulnerabilities?
SELECT domain, COUNT(DISTINCT library_has_vulnerabilities.vulnerability_id) AS freq
    FROM domains
    JOIN domain_has_javascripts on domains.domain_id = domain_has_javascripts.domain_id
    JOIN javascript_is_library on domain_has_javascripts.javascript_hash = javascript_is_library.javascript_hash
    JOIN library_has_vulnerabilities on javascript_is_library.library_id = library_has_vulnerabilities.library_id
    GROUP BY domains.domain_id, domains.domain_id
    ORDER BY freq DESC;

-- Which vulnerabilities are the most frequent?
SELECT vulnerability_id,
	COUNT(vulnerability_id) AS Freq
    FROM library_has_vulnerabilities
    GROUP BY vulnerability_id
    ORDER BY Freq DESC
    LIMIT 5;

-- Which domains have the highest amount of "High" and "Critical" vulnerabilities?
SELECT domain, SUM(CASE WHEN javascript_vulnerabilities.severity >= 3 THEN 1 ELSE 0 END) AS SevFreq
    FROM domains
    JOIN domain_has_javascripts on domains.domain_id = domain_has_javascripts.domain_id
    JOIN javascript_is_library on domain_has_javascripts.javascript_hash = javascript_is_library.javascript_hash
    JOIN library_has_vulnerabilities on javascript_is_library.library_id = library_has_vulnerabilities.library_id
    JOIN javascript_vulnerabilities on library_has_vulnerabilities.vulnerability_id = javascript_vulnerabilities.vulnerability_id
    GROUP BY domains.domain_id, javascript_vulnerabilities.severity
    ORDER BY SevFreq DESC
    LIMIT 5;

-- Which identified libraries do not have any vulnerabilities?
SELECT libname, version
    FROM libraries
    WHERE library_id NOT IN
      (SELECT library_id FROM library_has_vulnerabilities);

-- How many websites are either inactive or are not meant to be accessed directly?
SELECT domain
    FROM domains
    WHERE domain_id NOT IN
      (SELECT domain_id FROM domain_has_javascripts)
  AND domain_id NOT IN
      (SELECT domain_id FROM cookies)
  AND domain_id NOT IN
      (SELECT domain_id FROM http_headers);

-- Which domains has the highest amount of red Privacy Badger actions?
SELECT domains.domain, COUNT(privacy_badger_actions.domain_id) AS freq
    FROM domains
    JOIN privacy_badger_actions on domains.domain_id = privacy_badger_actions.domain_id
    WHERE privacy_badger_actions.is_red = 1
    GROUP BY domains.domain
    ORDER BY freq DESC;

-- Which server software are the most used?
SELECT software, COUNT(software) AS freq
    FROM server_software
    GROUP BY software
    ORDER BY freq DESC;

-- Which server software cause the highest amount of vulnerabilities?
SELECT software, COUNT(server_software_has_server_vulnerabilities.software_hash) AS freq
    FROM server_software
    JOIN server_software_has_server_vulnerabilities on server_software.software_hash = server_software_has_server_vulnerabilities.software_hash
    GROUP BY software
    ORDER BY freq DESC;

-- Which CMSs are the most used?
SELECT cms_system, COUNT(cms_system) AS freq
    FROM identified_cms
    GROUP BY cms_system
    ORDER BY freq DESC;
