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

-- Hyppigst inkluderede js url
SELECT `url`, COUNT(`url`) AS `value_occurrence`
FROM `domain_has_javascripts`
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
    FROM domain_has_javascripts;

-- hvilke libraries har haft flest kendte vulnerabilities?
SELECT library_name, COUNT(library_name) AS freq
    FROM libraries
    JOIN library_has_vulnerabilities ON libraries.library_id = library_has_vulnerabilities.library_id
    GROUP BY library_name
    ORDER BY freq DESC
    LIMIT 99;

-- hvilke libraries er skyld i flest vulnerable sider?
SELECT library_name, COUNT(domains.domain_id) AS freq
    FROM libraries
    JOIN library_has_vulnerabilities ON libraries.library_id = library_has_vulnerabilities.library_id
    JOIN javascript_is_library ON library_has_vulnerabilities.library_id = javascript_is_library.library_id
    JOIN domain_has_javascripts ON javascript_is_library.javascript_hash = domain_has_javascripts.javascript_hash
    JOIN domains ON domain_has_javascripts.domain_id = domains.domain_id
    GROUP BY library_name
    ORDER BY freq DESC
    LIMIT 5;

-- Hvilke libraryversioner har flest kendte vulnerabilities?
SELECT libraries.library_name, libraries.library_version, COUNT(library_has_vulnerabilities.library_id) AS freq
    FROM libraries
    JOIN library_has_vulnerabilities ON libraries.library_id = library_has_vulnerabilities.library_id
    GROUP BY library_has_vulnerabilities.library_id
    ORDER BY freq DESC;

-- Hvilke domains har flest kendte unikke vulnerabilities?
SELECT domain, COUNT(DISTINCT library_has_vulnerabilities.vulnerability_id) AS freq
    FROM domains
    JOIN domain_has_javascripts on domains.domain_id = domain_has_javascripts.domain_id
    JOIN javascript_is_library on domain_has_javascripts.javascript_hash = javascript_is_library.javascript_hash
    JOIN library_has_vulnerabilities on javascript_is_library.library_id = library_has_vulnerabilities.library_id
    GROUP BY domains.domain_id, domains.domain_id
    ORDER BY freq DESC;

-- Hvilke kendte vulnerabilities er de mest hyppige?
SELECT vulnerability_id,
	COUNT(vulnerability_id) AS Freq
    FROM library_has_vulnerabilities
    GROUP BY vulnerability_id
    ORDER BY Freq DESC
    LIMIT 5;

-- Hvilke sider har flest high eller værre vulnerabilities?
SELECT domain, SUM(CASE WHEN javascript_vulnerabilities.severity >= 3 THEN 1 ELSE 0 END) AS SevFreq
    FROM domains
    JOIN domain_has_javascripts on domains.domain_id = domain_has_javascripts.domain_id
    JOIN javascript_is_library on domain_has_javascripts.javascript_hash = javascript_is_library.javascript_hash
    JOIN library_has_vulnerabilities on javascript_is_library.library_id = library_has_vulnerabilities.library_id
    JOIN javascript_vulnerabilities on library_has_vulnerabilities.vulnerability_id = javascript_vulnerabilities.vulnerability_id
    GROUP BY domains.domain_id, javascript_vulnerabilities.severity
    ORDER BY SevFreq DESC
    LIMIT 5;

-- Hvilke libraries har vi fundet som ikke har vulnerabilities?
SELECT library_name, library_version
    FROM libraries
    WHERE library_id NOT IN
      (SELECT library_id FROM library_has_vulnerabilities);

-- Hvor mange sider giver ingen data
SELECT domain
    FROM domains
    WHERE domain_id NOT IN
      (SELECT domain_id FROM domain_has_javascripts)
  AND domain_id NOT IN
      (SELECT domain_id FROM cookies)
  AND title = '';

-- Hvilke domæner har flest røde privacy badger handlinger?
SELECT domains.domain, COUNT(privacy_badger_actions.domain_id) AS freq
    FROM domains
    JOIN privacy_badger_actions on domains.domain_id = privacy_badger_actions.domain_id
    WHERE privacy_badger_actions.is_red = 1
    GROUP BY domains.domain
    ORDER BY freq DESC;

-- hvilket serversoftware er mest brugt?
SELECT software, COUNT(software) AS freq
    FROM server_software
    GROUP BY software
    ORDER BY freq DESC;

-- Hvilket serversoftware er skyld i flest vulnerabilities?
SELECT software, COUNT(server_software_has_server_vulnerabilities.software_hash) AS freq
    FROM server_software
    JOIN server_software_has_server_vulnerabilities on server_software.software_hash = server_software_has_server_vulnerabilities.software_hash
    GROUP BY software
    ORDER BY freq DESC;

-- Hvilket cms system er mest brugt?
SELECT cms_system, COUNT(cms_system) AS freq
    FROM identified_cms
    GROUP BY cms_system
    ORDER BY freq DESC;
