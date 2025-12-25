"""Forensic SQL queries for browser profile extraction.

Combined queries for Firefox (Gecko) and Chromium-based browsers.
"""

# =============================================================================
# WebKit Timestamp Conversion (Chromium)
# =============================================================================
# Chromium uses WebKit timestamps (microseconds since 1601-01-01)
# Unix epoch is 1970-01-01
# Difference: 11644473600 seconds

WEBKIT_TO_UNIX = 11644473600


def webkit_to_unix(webkit_timestamp: int) -> int:
    """Convert WebKit timestamp to Unix timestamp."""
    if webkit_timestamp == 0:
        return 0
    return (webkit_timestamp // 1000000) - WEBKIT_TO_UNIX


# =============================================================================
# FIREFOX QUERIES (places.sqlite, cookies.sqlite, etc.)
# =============================================================================

FIREFOX_QUERIES = {
    "places.sqlite": {
        "browsing_history": """
            SELECT 
                p.id, p.url, p.title,
                datetime(h.visit_date/1000000, 'unixepoch') as visit_time,
                CASE 
                    WHEN h.visit_type = 1 THEN 'link'
                    WHEN h.visit_type = 2 THEN 'typed'
                    WHEN h.visit_type = 3 THEN 'bookmark'
                    WHEN h.visit_type = 4 THEN 'redirect'
                    ELSE 'other'
                END as visit_type,
                p.visit_count as total_visits,
                datetime(p.last_visit_date/1000000, 'unixepoch') as last_visit
            FROM moz_historyvisits h
            JOIN moz_places p ON h.place_id = p.id
            ORDER BY h.visit_date DESC
        """,
        "bookmarks": """
            SELECT 
                b.id, b.title, p.url,
                datetime(b.dateAdded/1000, 'unixepoch') as created,
                datetime(b.lastModified/1000, 'unixepoch') as modified,
                CASE WHEN b.type = 1 THEN 'URL' WHEN b.type = 2 THEN 'Folder' ELSE 'Other' END as type
            FROM moz_bookmarks b
            LEFT JOIN moz_places p ON b.fk = p.id
            ORDER BY b.dateAdded DESC
        """,
        "top_sites": """
            SELECT url, title, visit_count, 
                   datetime(last_visit_date/1000000, 'unixepoch') as last_visit
            FROM moz_places
            WHERE url NOT LIKE 'about:%' AND url NOT LIKE 'file:%'
            ORDER BY visit_count DESC LIMIT 200
        """,
        "recent_24h": """
            SELECT p.url, p.title, datetime(h.visit_date/1000000, 'unixepoch') as visit_time
            FROM moz_historyvisits h
            JOIN moz_places p ON h.place_id = p.id
            WHERE h.visit_date > (strftime('%s', 'now') - 86400) * 1000000
            ORDER BY h.visit_date DESC
        """,
        "downloads": """
            SELECT DISTINCT url, title, datetime(last_visit_date/1000000, 'unixepoch') as accessed
            FROM moz_places
            WHERE url LIKE '%download%' OR title LIKE '%download%'
            ORDER BY last_visit_date DESC
        """,
        "search_queries": """
            SELECT DISTINCT url, title, visit_count, datetime(last_visit_date/1000000, 'unixepoch') as accessed
            FROM moz_places
            WHERE url LIKE '%search%' OR url LIKE '%google.com%' OR url LIKE '%bing.com%'
            ORDER BY last_visit_date DESC LIMIT 500
        """,
    },
    "cookies.sqlite": {
        "all_cookies": """
            SELECT id, name, value, host, path,
                   datetime(creationTime/1000000, 'unixepoch') as created,
                   datetime(lastAccessed/1000000, 'unixepoch') as accessed,
                   CASE WHEN expiry = 0 THEN 'Session' ELSE datetime(expiry, 'unixepoch') END as expires,
                   CASE WHEN isSecure = 1 THEN 'Yes' ELSE 'No' END as secure,
                   CASE WHEN isHttpOnly = 1 THEN 'Yes' ELSE 'No' END as httponly
            FROM moz_cookies ORDER BY lastAccessed DESC
        """,
        "auth_tokens": """
            SELECT host, name, value, datetime(creationTime/1000000, 'unixepoch') as created,
                   CASE WHEN expiry = 0 THEN 'Session' ELSE datetime(expiry, 'unixepoch') END as expires
            FROM moz_cookies
            WHERE name LIKE '%token%' OR name LIKE '%session%' OR name LIKE '%auth%' OR name LIKE '%jwt%'
            ORDER BY creationTime DESC
        """,
        "cookies_by_domain": """
            SELECT host, COUNT(*) as count, GROUP_CONCAT(name, ', ') as cookies,
                   MAX(datetime(lastAccessed/1000000, 'unixepoch')) as accessed
            FROM moz_cookies GROUP BY host ORDER BY count DESC
        """,
    },
    "formhistory.sqlite": {
        "all_form_history": """
            SELECT id, fieldname, value, timesUsed,
                   datetime(firstUsed/1000000, 'unixepoch') as first_used,
                   datetime(lastUsed/1000000, 'unixepoch') as last_used
            FROM moz_formhistory ORDER BY lastUsed DESC
        """,
        "sensitive_fields": """
            SELECT fieldname, value, timesUsed,
                   datetime(lastUsed/1000000, 'unixepoch') as last_used
            FROM moz_formhistory
            WHERE fieldname LIKE '%email%' OR fieldname LIKE '%user%' 
               OR fieldname LIKE '%phone%' OR fieldname LIKE '%address%'
            ORDER BY lastUsed DESC
        """,
        "search_queries": """
            SELECT value as query, timesUsed as count,
                   datetime(firstUsed/1000000, 'unixepoch') as first,
                   datetime(lastUsed/1000000, 'unixepoch') as last
            FROM moz_formhistory
            WHERE fieldname LIKE '%search%' OR fieldname LIKE '%q%'
            ORDER BY timesUsed DESC LIMIT 500
        """,
        "email_addresses": """
            SELECT DISTINCT value as email, timesUsed, datetime(lastUsed/1000000, 'unixepoch') as last
            FROM moz_formhistory
            WHERE value LIKE '%@%.%' AND LENGTH(value) < 100 AND LENGTH(value) > 5
            ORDER BY lastUsed DESC
        """,
    },
    "permissions.sqlite": {
        "all_permissions": """
            SELECT origin, type,
                   CASE WHEN permission = 1 THEN 'Allow' WHEN permission = 2 THEN 'Deny' ELSE 'Prompt' END as status,
                   datetime(modificationTime/1000, 'unixepoch') as modified
            FROM moz_perms ORDER BY modificationTime DESC
        """,
        "granted_permissions": """
            SELECT origin, type, datetime(modificationTime/1000, 'unixepoch') as granted
            FROM moz_perms WHERE permission = 1 ORDER BY modificationTime DESC
        """,
        "geolocation": """
            SELECT origin, CASE WHEN permission = 1 THEN 'Allowed' ELSE 'Denied' END as status,
                   datetime(modificationTime/1000, 'unixepoch') as modified
            FROM moz_perms WHERE type = 'geo' ORDER BY modificationTime DESC
        """,
        "media_devices": """
            SELECT origin, type, CASE WHEN permission = 1 THEN 'Allowed' ELSE 'Denied' END as status
            FROM moz_perms WHERE type IN ('camera', 'microphone', 'screen')
            ORDER BY modificationTime DESC
        """,
    },
}


# =============================================================================
# CHROMIUM QUERIES (History, Cookies, Login Data, etc.)
# =============================================================================

CHROMIUM_QUERIES = {
    "History": {
        "browsing_history": """
            SELECT u.id, u.url, u.title,
                   datetime((v.visit_time/1000000)-11644473600, 'unixepoch') as visit_time,
                   CASE v.transition & 0xFF
                       WHEN 0 THEN 'link' WHEN 1 THEN 'typed' WHEN 7 THEN 'form_submit'
                       ELSE 'other' END as transition,
                   u.visit_count, u.typed_count,
                   datetime((u.last_visit_time/1000000)-11644473600, 'unixepoch') as last_visit
            FROM visits v JOIN urls u ON v.url = u.id ORDER BY v.visit_time DESC
        """,
        "top_sites": """
            SELECT url, title, visit_count, typed_count,
                   datetime((last_visit_time/1000000)-11644473600, 'unixepoch') as last_visit
            FROM urls WHERE url NOT LIKE 'chrome://%' AND url NOT LIKE 'chrome-extension://%'
            ORDER BY visit_count DESC LIMIT 200
        """,
        "typed_urls": """
            SELECT url, title, typed_count, visit_count,
                   datetime((last_visit_time/1000000)-11644473600, 'unixepoch') as last_visit
            FROM urls WHERE typed_count > 0 ORDER BY typed_count DESC
        """,
        "recent_24h": """
            SELECT u.url, u.title, datetime((v.visit_time/1000000)-11644473600, 'unixepoch') as visit_time
            FROM visits v JOIN urls u ON v.url = u.id
            WHERE v.visit_time > ((strftime('%s','now')+11644473600)*1000000 - 86400000000)
            ORDER BY v.visit_time DESC
        """,
        "downloads": """
            SELECT d.id, d.target_path,
                   datetime((d.start_time/1000000)-11644473600, 'unixepoch') as start_time,
                   datetime((d.end_time/1000000)-11644473600, 'unixepoch') as end_time,
                   d.received_bytes, d.total_bytes,
                   CASE d.state WHEN 1 THEN 'complete' WHEN 2 THEN 'cancelled' ELSE 'other' END as state,
                   d.mime_type, dc.url as url
            FROM downloads d
            LEFT JOIN downloads_url_chains dc ON d.id = dc.id AND dc.chain_index = 0
            ORDER BY d.start_time DESC
        """,
        "search_queries": """
            SELECT DISTINCT url, title, visit_count,
                   datetime((last_visit_time/1000000)-11644473600, 'unixepoch') as last_visit
            FROM urls
            WHERE url LIKE '%google.com/search%' OR url LIKE '%bing.com/search%' 
               OR url LIKE '%duckduckgo.com/%'
            ORDER BY last_visit_time DESC
        """,
    },
    "Cookies": {
        "all_cookies": """
            SELECT host_key, name, path, encrypted_value,
                   datetime((creation_utc/1000000)-11644473600, 'unixepoch') as created,
                   datetime((expires_utc/1000000)-11644473600, 'unixepoch') as expires,
                   datetime((last_access_utc/1000000)-11644473600, 'unixepoch') as accessed,
                   is_secure, is_httponly,
                   CASE samesite WHEN 1 THEN 'lax' WHEN 2 THEN 'strict' ELSE 'none' END as samesite
            FROM cookies ORDER BY last_access_utc DESC
        """,
        "session_cookies": """
            SELECT host_key, name, encrypted_value,
                   datetime((creation_utc/1000000)-11644473600, 'unixepoch') as created,
                   is_secure, is_httponly
            FROM cookies WHERE is_persistent = 0 OR expires_utc = 0 ORDER BY last_access_utc DESC
        """,
        "cookies_by_domain": """
            SELECT host_key, COUNT(*) as count,
                   MAX(datetime((last_access_utc/1000000)-11644473600, 'unixepoch')) as accessed
            FROM cookies GROUP BY host_key ORDER BY count DESC LIMIT 100
        """,
        "auth_cookies": """
            SELECT host_key, name, encrypted_value, path,
                   datetime((creation_utc/1000000)-11644473600, 'unixepoch') as created,
                   datetime((expires_utc/1000000)-11644473600, 'unixepoch') as expires,
                   is_secure, is_httponly
            FROM cookies 
            WHERE name LIKE '%token%' OR name LIKE '%session%' OR name LIKE '%auth%' 
               OR name LIKE '%jwt%' OR name LIKE '%sid%' OR name LIKE '%login%'
            ORDER BY last_access_utc DESC
        """,
    },
    "Login Data": {
        "all_logins": """
            SELECT origin_url, action_url, username_element, username_value,
                   password_element, password_value, signon_realm,
                   datetime((date_created/1000000)-11644473600, 'unixepoch') as created,
                   datetime((date_last_used/1000000)-11644473600, 'unixepoch') as last_used,
                   times_used, blacklisted_by_user
            FROM logins ORDER BY date_last_used DESC
        """,
        "active_logins": """
            SELECT signon_realm, origin_url, username_value,
                   datetime((date_created/1000000)-11644473600, 'unixepoch') as created,
                   datetime((date_last_used/1000000)-11644473600, 'unixepoch') as last_used,
                   times_used
            FROM logins WHERE blacklisted_by_user = 0 ORDER BY times_used DESC
        """,
    },
    "Web Data": {
        "autofill": """
            SELECT name, value, count,
                   datetime((date_created/1000000)-11644473600, 'unixepoch') as first_used,
                   datetime((date_last_used/1000000)-11644473600, 'unixepoch') as last_used
            FROM autofill ORDER BY count DESC
        """,
        "autofill_emails": """
            SELECT DISTINCT value as email, count as times_used,
                   datetime((date_last_used/1000000)-11644473600, 'unixepoch') as last_used
            FROM autofill
            WHERE name LIKE '%email%' OR value LIKE '%@%.%' ORDER BY count DESC
        """,
        "autofill_profiles": """
            SELECT guid, company_name, street_address, city, state, zipcode, country_code,
                   use_count, datetime((use_date/1000000)-11644473600, 'unixepoch') as last_used
            FROM autofill_profiles ORDER BY use_count DESC
        """,
        "credit_cards": """
            SELECT guid, name_on_card, expiration_month, expiration_year,
                   use_count, datetime((use_date/1000000)-11644473600, 'unixepoch') as last_used
            FROM credit_cards ORDER BY use_count DESC
        """,
    },
}


# Legacy compatibility alias
QUERY_REGISTRY = FIREFOX_QUERIES
CHROMIUM_QUERY_REGISTRY = {
    cat: {"database": cat if cat != "Login Data" else "Login Data", "queries": {k: {"name": k, "query": v, "description": k} for k, v in queries.items()}}
    for cat, queries in CHROMIUM_QUERIES.items()
}
