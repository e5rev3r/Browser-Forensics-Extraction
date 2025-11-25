"""Forensic SQL queries for Firefox profile extraction."""

# ============================================================================
# places.sqlite Queries
# ============================================================================

PLACES_HISTORY_ALL = """
SELECT 
  p.id,
  p.url,
  p.title,
  datetime(h.visit_date/1000000, 'unixepoch') as visit_time,
  CASE 
    WHEN h.visit_type = 1 THEN 'link'
    WHEN h.visit_type = 2 THEN 'typed'
    WHEN h.visit_type = 3 THEN 'bookmark'
    WHEN h.visit_type = 4 THEN 'redirect'
    WHEN h.visit_type = 5 THEN 'forward'
    WHEN h.visit_type = 6 THEN 'reload'
    ELSE 'unknown'
  END as visit_type,
  p.visit_count as total_visits,
  datetime(p.last_visit_date/1000000, 'unixepoch') as last_visit_recorded
FROM moz_historyvisits h
JOIN moz_places p ON h.place_id = p.id
ORDER BY h.visit_date DESC
"""

PLACES_BOOKMARKS = """
SELECT 
  b.id,
  b.title,
  p.url,
  datetime(b.dateAdded/1000, 'unixepoch') as created,
  datetime(b.lastModified/1000, 'unixepoch') as last_modified,
  b.guid,
  CASE 
    WHEN b.type = 1 THEN 'URL'
    WHEN b.type = 2 THEN 'Folder'
    WHEN b.type = 3 THEN 'Separator'
    ELSE 'Unknown'
  END as entry_type
FROM moz_bookmarks b
LEFT JOIN moz_places p ON b.fk = p.id
ORDER BY b.dateAdded DESC
"""

PLACES_TOP_SITES = """
SELECT 
  url,
  title,
  visit_count,
  datetime(last_visit_date/1000000, 'unixepoch') as last_visit,
  frecency
FROM moz_places
WHERE url NOT LIKE 'about:%' 
  AND url NOT LIKE 'file:%'
  AND url NOT LIKE 'chrome:%'
ORDER BY visit_count DESC
LIMIT 200
"""

PLACES_RECENT_24H = """
SELECT 
  p.url,
  p.title,
  datetime(h.visit_date/1000000, 'unixepoch') as visit_time,
  CASE 
    WHEN h.visit_type = 2 THEN 'User Typed'
    WHEN h.visit_type = 1 THEN 'Link Clicked'
    WHEN h.visit_type = 4 THEN 'Redirect'
    ELSE 'Other'
  END as user_action
FROM moz_historyvisits h
JOIN moz_places p ON h.place_id = p.id
WHERE h.visit_date > (strftime('%s', 'now') - 86400) * 1000000
ORDER BY h.visit_date DESC
"""

PLACES_DOWNLOADS = """
SELECT DISTINCT
  url,
  title,
  datetime(last_visit_date/1000000, 'unixepoch') as last_accessed
FROM moz_places
WHERE (url LIKE '%download%' OR title LIKE '%download%')
  AND url NOT LIKE 'about:%'
ORDER BY last_visit_date DESC
"""

PLACES_SEARCH_QUERIES = """
SELECT DISTINCT
  url,
  title,
  visit_count,
  datetime(last_visit_date/1000000, 'unixepoch') as last_accessed
FROM moz_places
WHERE url LIKE '%search%' 
  OR url LIKE '%google.com%'
  OR url LIKE '%bing.com%'
  OR url LIKE '%duckduckgo.com%'
ORDER BY last_visit_date DESC
LIMIT 500
"""

PLACES_REFERRER_CHAINS = """
SELECT 
  p.url,
  p.title,
  datetime(h.visit_date/1000000, 'unixepoch') as visit_time,
  CASE 
    WHEN ref.url IS NULL THEN '(direct/typed)'
    ELSE ref.url
  END as referrer_url,
  CASE 
    WHEN ref.title IS NULL THEN ''
    ELSE ref.title
  END as referrer_title
FROM moz_historyvisits h
JOIN moz_places p ON h.place_id = p.id
LEFT JOIN moz_historyvisits ref_h ON h.from_visit = ref_h.id
LEFT JOIN moz_places ref ON ref_h.place_id = ref.id
ORDER BY h.visit_date DESC
LIMIT 1000
"""

# ============================================================================
# cookies.sqlite Queries
# ============================================================================

COOKIES_ALL = """
SELECT 
  id,
  name,
  value,
  host,
  path,
  datetime(creationTime/1000000, 'unixepoch') as created,
  datetime(lastAccessed/1000000, 'unixepoch') as last_accessed,
  CASE 
    WHEN expiry = 0 THEN 'Session'
    ELSE datetime(expiry, 'unixepoch')
  END as expiry_date,
  CASE WHEN isSecure = 1 THEN 'Yes' ELSE 'No' END as secure_flag,
  CASE WHEN isHttpOnly = 1 THEN 'Yes' ELSE 'No' END as httponly_flag,
  CASE WHEN sameSite = 0 THEN 'None'
       WHEN sameSite = 1 THEN 'Lax'
       WHEN sameSite = 2 THEN 'Strict'
       ELSE 'Unknown'
  END as samesite_policy
FROM moz_cookies
ORDER BY lastAccessed DESC
"""

COOKIES_AUTH_TOKENS = """
SELECT 
  host,
  name,
  value,
  datetime(creationTime/1000000, 'unixepoch') as created,
  CASE 
    WHEN expiry = 0 THEN 'Session'
    ELSE datetime(expiry, 'unixepoch')
  END as expires,
  CASE WHEN isHttpOnly = 1 THEN 'Protected' ELSE 'Exposed' END as protection
FROM moz_cookies
WHERE name LIKE '%token%' 
   OR name LIKE '%session%' 
   OR name LIKE '%auth%'
   OR name LIKE '%key%'
   OR name LIKE '%jwt%'
   OR name LIKE '%bearer%'
ORDER BY creationTime DESC
"""

COOKIES_PERSISTENT_SESSIONS = """
SELECT 
  host,
  name,
  value,
  datetime(creationTime/1000000, 'unixepoch') as created,
  datetime(lastAccessed/1000000, 'unixepoch') as last_accessed,
  CASE 
    WHEN expiry = 0 THEN 'Session'
    ELSE datetime(expiry, 'unixepoch')
  END as expires
FROM moz_cookies
WHERE (name LIKE '%token%' OR name LIKE '%session%' OR name LIKE '%auth%')
  AND isHttpOnly = 1
  AND expiry > 0
ORDER BY lastAccessed DESC
"""

COOKIES_BY_DOMAIN = """
SELECT 
  host,
  COUNT(*) as cookie_count,
  GROUP_CONCAT(name, ', ') as cookie_names,
  MAX(datetime(lastAccessed/1000000, 'unixepoch')) as last_accessed
FROM moz_cookies
GROUP BY host
ORDER BY cookie_count DESC
"""

# ============================================================================
# formhistory.sqlite Queries
# ============================================================================

FORMHISTORY_ALL = """
SELECT 
  id,
  fieldname,
  value,
  timesUsed,
  datetime(firstUsed/1000000, 'unixepoch') as first_used,
  datetime(lastUsed/1000000, 'unixepoch') as last_used,
  guid
FROM moz_formhistory
ORDER BY lastUsed DESC
"""

FORMHISTORY_SENSITIVE = """
SELECT 
  fieldname,
  value,
  timesUsed,
  datetime(firstUsed/1000000, 'unixepoch') as first_used,
  datetime(lastUsed/1000000, 'unixepoch') as last_used
FROM moz_formhistory
WHERE fieldname LIKE '%email%' 
   OR fieldname LIKE '%username%' 
   OR fieldname LIKE '%user%'
   OR fieldname LIKE '%phone%' 
   OR fieldname LIKE '%address%'
   OR fieldname LIKE '%card%'
   OR fieldname LIKE '%cvv%'
   OR fieldname LIKE '%zip%'
ORDER BY lastUsed DESC
"""

FORMHISTORY_SEARCHES = """
SELECT 
  value as search_term,
  timesUsed as frequency,
  datetime(firstUsed/1000000, 'unixepoch') as first_search,
  datetime(lastUsed/1000000, 'unixepoch') as last_search,
  CAST((lastUsed - firstUsed) / 86400000000.0 AS INTEGER) as days_active
FROM moz_formhistory
WHERE fieldname LIKE '%search%' 
   OR fieldname LIKE '%query%'
   OR fieldname LIKE '%q%'
ORDER BY timesUsed DESC
LIMIT 500
"""

FORMHISTORY_EMAILS = """
SELECT DISTINCT
  value as email_address,
  timesUsed,
  datetime(lastUsed/1000000, 'unixepoch') as last_used
FROM moz_formhistory
WHERE value LIKE '%@%.%' 
  AND LENGTH(value) < 100
  AND LENGTH(value) > 5
ORDER BY lastUsed DESC
"""

# ============================================================================
# permissions.sqlite Queries
# ============================================================================

PERMISSIONS_ALL = """
SELECT 
  origin,
  type,
  CASE 
    WHEN permission = 1 THEN 'Allow'
    WHEN permission = 2 THEN 'Deny'
    WHEN permission = 3 THEN 'Prompt'
    WHEN permission = 4 THEN 'Allow Default'
    ELSE 'Unknown'
  END as status,
  CASE 
    WHEN expireType = 0 THEN 'Permanent'
    WHEN expireType = 1 THEN 'Session'
    WHEN expireType = 2 THEN datetime(expireTime/1000, 'unixepoch')
    ELSE 'Unknown'
  END as expiration,
  datetime(modificationTime/1000, 'unixepoch') as modified_date
FROM moz_perms
ORDER BY modificationTime DESC
"""

PERMISSIONS_GRANTED = """
SELECT 
  origin,
  type,
  datetime(modificationTime/1000, 'unixepoch') as granted_date,
  CASE 
    WHEN expireType = 0 THEN 'Permanent'
    WHEN expireType = 1 THEN 'Session'
    WHEN expireType = 2 THEN datetime(expireTime/1000, 'unixepoch')
    ELSE 'Unknown'
  END as expires
FROM moz_perms
WHERE permission = 1
ORDER BY modificationTime DESC
"""

PERMISSIONS_GEOLOCATION = """
SELECT 
  origin,
  CASE WHEN permission = 1 THEN 'Allowed' ELSE 'Denied' END as status,
  datetime(modificationTime/1000, 'unixepoch') as modified,
  CASE 
    WHEN expireType = 0 THEN 'Permanent'
    WHEN expireType = 1 THEN 'Session'
    WHEN expireType = 2 THEN datetime(expireTime/1000, 'unixepoch')
    ELSE 'Unknown'
  END as expiration
FROM moz_perms
WHERE type = 'geo'
ORDER BY modificationTime DESC
"""

PERMISSIONS_MEDIA_DEVICES = """
SELECT 
  origin,
  type,
  CASE WHEN permission = 1 THEN 'Allowed' ELSE 'Denied' END as status,
  datetime(modificationTime/1000, 'unixepoch') as modified
FROM moz_perms
WHERE type IN ('camera', 'microphone', 'screen', 'speaker-selection')
ORDER BY modificationTime DESC
"""

PERMISSIONS_NOTIFICATIONS = """
SELECT 
  origin,
  CASE WHEN permission = 1 THEN 'Allowed' ELSE 'Denied' END as status,
  datetime(modificationTime/1000, 'unixepoch') as modified
FROM moz_perms
WHERE type = 'desktop-notification'
ORDER BY modificationTime DESC
"""

# ============================================================================
# storage.sqlite Queries
# ============================================================================

STORAGE_LOCALSTORAGE = """
SELECT 
  o.origin,
  o.group_ as origin_group,
  o.usage as storage_bytes,
  datetime(o.last_access_time/1000000, 'unixepoch') as last_accessed,
  o.persisted,
  r.id as repository_type
FROM origin o
JOIN repository r ON o.repository_id = r.id
WHERE r.id = 2
ORDER BY o.last_access_time DESC
"""

STORAGE_ORIGINS = """
SELECT 
  o.origin,
  o.group_ as origin_group,
  o.usage as storage_bytes,
  datetime(o.last_access_time/1000000, 'unixepoch') as last_accessed,
  o.persisted,
  r.id as repository_type
FROM origin o
JOIN repository r ON o.repository_id = r.id
ORDER BY o.usage DESC
"""

# ============================================================================
# webappsstore.sqlite Queries (Legacy localStorage)
# ============================================================================

WEBAPPSSTORE_ALL = """
SELECT 
  originKey as origin,
  scope,
  key,
  value,
  originAttributes as context
FROM webappsstore2
ORDER BY originKey, key
"""

# ============================================================================
# favicons.sqlite Queries
# ============================================================================

FAVICONS_MAPPING = """
SELECT 
  i.id,
  i.icon_url as favicon_url,
  i.width,
  length(i.data) as data_size_bytes,
  datetime(i.expire_ms/1000, 'unixepoch') as cache_expires,
  p.page_url
FROM moz_icons i
LEFT JOIN moz_icons_to_pages ip ON i.id = ip.icon_id
LEFT JOIN moz_pages_w_icons p ON ip.page_id = p.id
ORDER BY i.expire_ms DESC
"""

# ============================================================================
# CREDENTIAL-FOCUSED QUERIES (For highlighting sensitive data)
# ============================================================================

# Find all login-related URLs from history
PLACES_LOGIN_URLS = """
SELECT 
  url,
  title,
  visit_count,
  datetime(last_visit_date/1000000, 'unixepoch') as last_visit
FROM moz_places
WHERE url LIKE '%login%' 
   OR url LIKE '%signin%'
   OR url LIKE '%sign-in%'
   OR url LIKE '%auth%'
   OR url LIKE '%account%'
   OR url LIKE '%password%'
   OR url LIKE '%register%'
   OR url LIKE '%signup%'
ORDER BY last_visit_date DESC
"""

# Find authentication cookies (high priority)
COOKIES_AUTH_HIGH_PRIORITY = """
SELECT 
  host,
  name,
  CASE 
    WHEN length(value) > 50 THEN substr(value, 1, 50) || '...'
    ELSE value
  END as value_preview,
  value as full_value,
  datetime(creationTime/1000000, 'unixepoch') as created,
  datetime(lastAccessed/1000000, 'unixepoch') as last_accessed,
  CASE 
    WHEN expiry = 0 THEN 'Session'
    ELSE datetime(expiry, 'unixepoch')
  END as expires,
  'HIGH PRIORITY' as priority
FROM moz_cookies
WHERE (
  name LIKE '%session%id%'
  OR name LIKE '%auth%token%'
  OR name LIKE '%access%token%'
  OR name LIKE '%refresh%token%'
  OR name LIKE '%jwt%'
  OR name LIKE '%bearer%'
  OR name LIKE '%api%key%'
  OR name LIKE '%secret%'
  OR name LIKE '%password%'
  OR name = 'PHPSESSID'
  OR name = 'JSESSIONID'
  OR name LIKE '%_session'
  OR name LIKE 'sess_%'
)
ORDER BY lastAccessed DESC
"""

# Find all email addresses in form history
FORMHISTORY_ALL_EMAILS = """
SELECT 
  value as email,
  fieldname,
  timesUsed as times_used,
  datetime(firstUsed/1000000, 'unixepoch') as first_entry,
  datetime(lastUsed/1000000, 'unixepoch') as last_entry,
  'EMAIL' as credential_type
FROM moz_formhistory
WHERE value LIKE '%@%'
  AND (
    value LIKE '%@gmail.%'
    OR value LIKE '%@yahoo.%'
    OR value LIKE '%@hotmail.%'
    OR value LIKE '%@outlook.%'
    OR value LIKE '%@proton%'
    OR value LIKE '%@icloud.%'
    OR value LIKE '%@%.com'
    OR value LIKE '%@%.org'
    OR value LIKE '%@%.net'
    OR value LIKE '%@%.edu'
    OR value LIKE '%@%.io'
  )
  AND length(value) < 100
ORDER BY timesUsed DESC
"""

# Find usernames in form history
FORMHISTORY_USERNAMES = """
SELECT 
  fieldname,
  value as username,
  timesUsed as times_used,
  datetime(lastUsed/1000000, 'unixepoch') as last_used,
  'USERNAME' as credential_type
FROM moz_formhistory
WHERE (
  fieldname LIKE '%user%'
  OR fieldname LIKE '%login%'
  OR fieldname LIKE '%email%'
  OR fieldname LIKE '%account%'
  OR fieldname = 'username'
  OR fieldname = 'user'
  OR fieldname = 'login'
  OR fieldname = 'email'
  OR fieldname = 'id'
)
AND length(value) < 100
AND length(value) > 2
ORDER BY timesUsed DESC
"""

# Find sensitive personal info in forms
FORMHISTORY_PERSONAL_INFO = """
SELECT 
  fieldname,
  value,
  timesUsed,
  datetime(lastUsed/1000000, 'unixepoch') as last_used,
  CASE
    WHEN fieldname LIKE '%phone%' OR fieldname LIKE '%mobile%' OR fieldname LIKE '%tel%' THEN 'PHONE'
    WHEN fieldname LIKE '%address%' OR fieldname LIKE '%street%' OR fieldname LIKE '%city%' THEN 'ADDRESS'
    WHEN fieldname LIKE '%card%' OR fieldname LIKE '%credit%' OR fieldname LIKE '%debit%' THEN 'PAYMENT'
    WHEN fieldname LIKE '%ssn%' OR fieldname LIKE '%social%' THEN 'SSN'
    WHEN fieldname LIKE '%dob%' OR fieldname LIKE '%birth%' OR fieldname LIKE '%date%' THEN 'DOB'
    WHEN fieldname LIKE '%name%' THEN 'NAME'
    ELSE 'OTHER'
  END as data_type
FROM moz_formhistory
WHERE (
  fieldname LIKE '%phone%'
  OR fieldname LIKE '%mobile%'
  OR fieldname LIKE '%tel%'
  OR fieldname LIKE '%address%'
  OR fieldname LIKE '%street%'
  OR fieldname LIKE '%city%'
  OR fieldname LIKE '%state%'
  OR fieldname LIKE '%zip%'
  OR fieldname LIKE '%postal%'
  OR fieldname LIKE '%card%'
  OR fieldname LIKE '%credit%'
  OR fieldname LIKE '%cvv%'
  OR fieldname LIKE '%ssn%'
  OR fieldname LIKE '%social%'
  OR fieldname LIKE '%birth%'
  OR fieldname LIKE '%dob%'
  OR fieldname LIKE '%firstname%'
  OR fieldname LIKE '%lastname%'
  OR fieldname LIKE '%fullname%'
)
ORDER BY lastUsed DESC
"""

# Find sites with sensitive permissions granted
PERMISSIONS_SENSITIVE = """
SELECT 
  origin,
  type as permission_type,
  CASE WHEN permission = 1 THEN 'GRANTED' ELSE 'DENIED' END as status,
  datetime(modificationTime/1000, 'unixepoch') as granted_date,
  'SENSITIVE PERMISSION' as alert
FROM moz_perms
WHERE type IN (
  'geo',
  'camera',
  'microphone',
  'screen',
  'clipboard-read',
  'clipboard-write',
  'persistent-storage',
  'notifications'
)
AND permission = 1
ORDER BY modificationTime DESC
"""

# ============================================================================
# Query Registry (maps database name and profile section to queries)
# ============================================================================

QUERY_REGISTRY = {
    "places.sqlite": {
        "browsing_history": PLACES_HISTORY_ALL,
        "bookmarks": PLACES_BOOKMARKS,
        "top_sites": PLACES_TOP_SITES,
        "recent_24h": PLACES_RECENT_24H,
        "downloads": PLACES_DOWNLOADS,
        "search_queries": PLACES_SEARCH_QUERIES,
        "referrer_chains": PLACES_REFERRER_CHAINS,
        "login_urls": PLACES_LOGIN_URLS,
    },
    "cookies.sqlite": {
        "all_cookies": COOKIES_ALL,
        "auth_tokens": COOKIES_AUTH_TOKENS,
        "persistent_sessions": COOKIES_PERSISTENT_SESSIONS,
        "cookies_by_domain": COOKIES_BY_DOMAIN,
        "auth_high_priority": COOKIES_AUTH_HIGH_PRIORITY,
    },
    "formhistory.sqlite": {
        "all_form_history": FORMHISTORY_ALL,
        "sensitive_fields": FORMHISTORY_SENSITIVE,
        "search_queries": FORMHISTORY_SEARCHES,
        "email_addresses": FORMHISTORY_EMAILS,
        "all_emails": FORMHISTORY_ALL_EMAILS,
        "usernames": FORMHISTORY_USERNAMES,
        "personal_info": FORMHISTORY_PERSONAL_INFO,
    },
    "permissions.sqlite": {
        "all_permissions": PERMISSIONS_ALL,
        "granted_permissions": PERMISSIONS_GRANTED,
        "geolocation": PERMISSIONS_GEOLOCATION,
        "media_devices": PERMISSIONS_MEDIA_DEVICES,
        "notifications": PERMISSIONS_NOTIFICATIONS,
        "sensitive_permissions": PERMISSIONS_SENSITIVE,
    },
    "storage.sqlite": {
        "localstorage": STORAGE_LOCALSTORAGE,
        "storage_origins": STORAGE_ORIGINS,
    },
    "favicons.sqlite": {
        "favicon_mapping": FAVICONS_MAPPING,
    },
    "webappsstore.sqlite": {
        "all_storage": WEBAPPSSTORE_ALL,
    },
}


def get_query(database: str, query_name: str) -> str | None:
    """Retrieve a forensic query by database name and query name.
    
    Args:
        database: Database filename (e.g., 'places.sqlite')
        query_name: Query identifier (e.g., 'browsing_history')
    
    Returns:
        SQL query string or None if not found.
    """
    return QUERY_REGISTRY.get(database, {}).get(query_name)


def list_queries(database: str | None = None) -> dict:
    """List all available queries or queries for a specific database.
    
    Args:
        database: Optional database name filter.
    
    Returns:
        Dictionary of available queries.
    """
    if database:
        return QUERY_REGISTRY.get(database, {})
    return QUERY_REGISTRY
