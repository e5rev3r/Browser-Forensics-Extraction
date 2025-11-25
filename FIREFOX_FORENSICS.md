# Firefox Profile Forensics

## Overview

Firefox profiles are located in `~/.mozilla/firefox/<profile-name>/`. Each profile contains critical forensic artifacts including browsing history, cookies, credentials, bookmarks, downloads, and cached content. Analysis of these files reveals user activity, authentication details, site preferences, and temporal data.

---

## Profile Directory Structure and File Inventory

### Core Configuration Files

#### `prefs.js`
- **Purpose**: User preferences and browser settings
- **Forensic Value**: High - Contains timezone, language, extensions, search engines, home page, custom preferences
- **Format**: JavaScript configuration file
- **Key Artifacts**: 
  - `intl.accept_languages`
  - `browser.startup.homepage`
  - `browser.newtab.preload`
  - All installed extension information

#### `user.js`
- **Purpose**: User-level preference overrides (optional)
- **Forensic Value**: Medium - Customizations and security settings
- **Format**: JavaScript
- **Key Artifacts**: Privacy settings, content blocking, DoH configuration

#### `compatibility.ini`
- **Purpose**: Tracks profile compatibility with Firefox versions
- **Forensic Value**: Low-Medium - Installation and update history
- **Format**: INI file
- **Key Data**: `LastVersion`, `LastPlatform`, `LastOSABI`

#### `extensions.json`
- **Purpose**: Installed and disabled extensions metadata
- **Forensic Value**: High - Third-party software analysis, user behavior profiling
- **Format**: JSON
- **Key Data**: Extension IDs, versions, installation dates, permissions

#### `extension-data/` directory
- **Purpose**: Per-extension data storage
- **Forensic Value**: Medium-High - Extension-specific user data, cache
- **Contents**: Subdirectories per extension ID with plugin data

#### `chrome/` directory
- **Purpose**: Custom user interface modifications (userChrome.css, userContent.css)
- **Forensic Value**: Low-Medium - Browser customization, CSS-based tracking/privacy mods

#### `chrome-settings-file.bin`
- **Purpose**: Binary storage of chrome settings
- **Forensic Value**: Low - Rarely recoverable data; typically requires proprietary parsing

### Database Files (SQLite)

#### `places.sqlite`
- **Purpose**: Browsing history, bookmarks, downloads, tags
- **Forensic Value**: Critical
- **Size Impact**: Primary historical record
- **Requires Recovery**: Yes, frequently

#### `cookies.sqlite`
- **Purpose**: HTTP cookies with domain, path, expiry, secure/httponly flags
- **Forensic Value**: Critical
- **Size Impact**: Medium
- **Requires Recovery**: Yes

#### `permissions.sqlite`
- **Purpose**: Site permissions (geolocation, camera, microphone, notifications, etc.)
- **Forensic Value**: Medium - Reveals user interaction with specific sites
- **Size Impact**: Small
- **Requires Recovery**: Yes

#### `storage.sqlite`
- **Purpose**: DOM storage (localStorage, sessionStorage), indexed DB metadata
- **Forensic Value**: Medium - Web application state and user input

#### `webappsstore.sqlite`
- **Purpose**: Legacy DOM storage (pre-storage.sqlite)
- **Forensic Value**: Low-Medium - Deprecated but may contain historical data

#### `handlers.json`
- **Purpose**: Protocol and MIME type handlers
- **Forensic Value**: Low - Application associations

#### `search.json`
- **Purpose**: Installed search engines and preferences
- **Forensic Value**: Low-Medium - User's preferred search providers

#### `addons.json`
- **Purpose**: Addon metadata (replaces extensions.json in newer versions)
- **Forensic Value**: High - Extension analysis

### Cache and Temporary Storage

#### `cache/` and `cache2/` directories
- **Purpose**: Cached web content (v2 is the current format)
- **Forensic Value**: Medium-High - Recoverable web pages, images, scripts
- **Structure**: Hashed subdirectories with index.sqlite
- **Recovery**: Cache entries have limited lifetime (per configuration)

#### `cache2/entries/` subdirectories
- **Purpose**: Individual cached resources
- **Forensic Value**: High - Web content recovery
- **Recovery**: Can be extracted with proper tools

#### `startupCache/` directory
- **Purpose**: Firefox startup performance cache
- **Forensic Value**: Low - Binary format

#### `OfflineCache/` directory
- **Purpose**: Offline-enabled website caches (HTML5 AppCache)
- **Forensic Value**: Medium - For sites using offline functionality

### Session and Tab State

#### `sessionstore.jsonlz4`
- **Purpose**: Current session state (tabs, windows, form data)
- **Forensic Value**: Medium-High - Active browsing state at profile closure
- **Compression**: LZ4 compressed JSON
- **Recovery**: Requires decompression

#### `recovery.jsonlz4`
- **Purpose**: Emergency session recovery
- **Forensic Value**: Medium - Last session state before crash

### Sync and Cloud Storage

#### `weave/` directory
- **Purpose**: Firefox Sync data and settings
- **Forensic Value**: Medium - Cross-device synchronization history
- **Contents**: Local copies of synced data before encryption

#### `logins.json`
- **Purpose**: Encrypted login credentials
- **Forensic Value**: Critical but encrypted
- **Encryption**: Master password or Windows DPAPI
- **Recovery**: Requires password cracking or key extraction

#### `logins.sqlite` (legacy)
- **Purpose**: Older format login storage
- **Forensic Value**: Critical but encrypted
- **Deprecation**: Replaced by logins.json in modern Firefox

### User Content and Profiles

#### `bookmarkbackups/` directory
- **Purpose**: Periodic automatic bookmarks backups
- **Forensic Value**: High - Historical bookmarks across multiple snapshots
- **Format**: JSON (gzipped)
- **Recovery**: Each file timestamped, named `bookmarks-<YYYYMMDD_HHMMSS>.json.gz`

#### `crashes/` directory
- **Purpose**: Crash reports and minidumps
- **Forensic Value**: Low-Medium - Application behavior and stability
- **Format**: JSON + binary dumps

#### `gmp/` directory
- **Purpose**: Gecko Media Plugins (DRM, audio/video)
- **Forensic Value**: Low
- **Contents**: Plugin metadata and binaries

#### `datareporting/` directory
- **Purpose**: Firefox telemetry and data reports
- **Forensic Value**: Low - Aggregated Firefox usage telemetry
- **Format**: JSON

#### `thumbnails/` directory
- **Purpose**: Thumbnail images of visited pages
- **Forensic Value**: Medium - Visual confirmation of visited sites
- **Format**: PNG files
- **Recovery**: Directly recoverable

#### `formhistory.sqlite`
- **Purpose**: Form input history (search terms, text fields)
- **Forensic Value**: High - User input patterns, queries, credentials drafts
- **Important**: May contain sensitive input before submission

#### `favicons.sqlite`
- **Purpose**: Website favicon metadata and cache
- **Forensic Value**: Low-Medium - Visited sites identification

### Metadata Files

#### `installs.ini`
- **Purpose**: Firefox installation date and build information
- **Forensic Value**: Low - Installation history
- **Key Data**: `InstallTime`, `BuildID`

#### `times.json`
- **Purpose**: Profile creation and access timestamps
- **Forensic Value**: Medium - Timeline establishment
- **Key Data**: `created`, `firstUse`

#### `.parentlock`
- **Purpose**: Lock file indicating active profile
- **Forensic Value**: Low - Indicates profile in use at analysis time

---

## Critical SQLite Databases: Detailed Analysis

### places.sqlite

**Purpose**: Central repository for all browsing history, bookmarks, downloads, and tags.

**Key Tables**:

| Table | Purpose |
|-------|---------|
| `moz_places` | URL entries with visit count and last visit time |
| `moz_historyvisits` | Individual visit records with timestamp and referrer |
| `moz_bookmarks` | Bookmark entries with titles, URLs, and folder structure |
| `moz_origins` | Origin-level statistics and frecency scores |

**Important Fields**:

- `moz_places.url`: Full URL string
- `moz_places.title`: Page title
- `moz_places.last_visit_date`: Timestamp (microseconds since epoch)
- `moz_places.visit_count`: Number of visits
- `moz_places.frecency`: Frecency score (frequency + recency)
- `moz_historyvisits.visit_date`: Individual visit timestamp
- `moz_historyvisits.visit_type`: Type (1=link, 2=typed, 3=bookmark, etc.)
- `moz_historyvisits.from_visit`: Referrer visit ID (for chain analysis)
- `moz_bookmarks.title`: Bookmark name
- `moz_bookmarks.type`: Entry type (1=URL, 2=folder, 3=separator)
- `moz_bookmarks.parent`: Parent folder ID
- `moz_bookmarks.dateAdded`: Bookmark creation timestamp
- `moz_bookmarks.lastModified`: Bookmark modification timestamp

**Recovery Commands**:

```bash
# List all tables
sqlite3 places.sqlite ".tables"

# Extract all browsing history with timestamps
sqlite3 places.sqlite << 'EOF'
SELECT 
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
  END as visit_type
FROM moz_historyvisits h
JOIN moz_places p ON h.place_id = p.id
ORDER BY h.visit_date DESC;
EOF
```

```bash
# Extract all bookmarks with hierarchy
sqlite3 places.sqlite << 'EOF'
SELECT 
  b.title,
  p.url,
  datetime(b.dateAdded/1000, 'unixepoch') as created,
  b.guid
FROM moz_bookmarks b
LEFT JOIN moz_places p ON b.fk = p.id
WHERE b.type = 1
ORDER BY b.dateAdded DESC;
EOF
```

```bash
# Extract download history (if stored)
sqlite3 places.sqlite << 'EOF'
SELECT 
  url,
  title,
  datetime(last_visit_date/1000000, 'unixepoch') as last_visit
FROM moz_places
WHERE title LIKE '%download%' OR url LIKE '%download%'
ORDER BY last_visit_date DESC;
EOF
```

```bash
# Extract visit chains (referrer analysis)
sqlite3 places.sqlite << 'EOF'
SELECT 
  p.url,
  p.title,
  datetime(h.visit_date/1000000, 'unixepoch') as visit_time,
  CASE 
    WHEN ref.url IS NULL THEN '(direct)'
    ELSE ref.url
  END as referrer_url
FROM moz_historyvisits h
JOIN moz_places p ON h.place_id = p.id
LEFT JOIN moz_historyvisits ref_h ON h.from_visit = ref_h.id
LEFT JOIN moz_places ref ON ref_h.place_id = ref.id
ORDER BY h.visit_date DESC
LIMIT 1000;
EOF
```

```bash
# Dump all tables and their content to CSV
sqlite3 -header -csv places.sqlite "SELECT * FROM moz_places" > places.csv
sqlite3 -header -csv places.sqlite "SELECT * FROM moz_historyvisits" > visits.csv
sqlite3 -header -csv places.sqlite "SELECT * FROM moz_bookmarks" > bookmarks.csv
```

---

### cookies.sqlite

**Purpose**: HTTP cookies, session cookies, and persistent authentication tokens.

**Key Tables**:

| Table | Purpose |
|-------|---------|
| `moz_cookies` | All stored cookies with domain and expiry |

**Important Fields**:

- `name`: Cookie name
- `value`: Cookie value (plaintext)
- `host`: Domain/subdomain
- `path`: URL path restriction
- `expiry`: Expiration timestamp (seconds since epoch, 0 = session)
- `lastAccessed`: Last access timestamp
- `creationTime`: Creation timestamp
- `isSecure`: HTTPS-only flag
- `isHttpOnly`: JavaScript inaccessible flag
- `inBrowserElementFlag`: Container isolation (if applicable)
- `sameSite`: SameSite policy value

**Recovery Commands**:

```bash
# List all cookies
sqlite3 cookies.sqlite << 'EOF'
SELECT 
  host,
  name,
  value,
  datetime(creationTime/1000000, 'unixepoch') as created,
  datetime(lastAccessed/1000000, 'unixepoch') as last_accessed,
  CASE 
    WHEN expiry = 0 THEN 'session'
    ELSE datetime(expiry, 'unixepoch')
  END as expiry,
  CASE WHEN isSecure = 1 THEN 'Secure' ELSE '' END as flags_secure,
  CASE WHEN isHttpOnly = 1 THEN 'HttpOnly' ELSE '' END as flags_httponly
FROM moz_cookies
ORDER BY lastAccessed DESC;
EOF
```

```bash
# Extract authentication tokens (common patterns)
sqlite3 cookies.sqlite << 'EOF'
SELECT 
  host,
  name,
  value,
  datetime(creationTime/1000000, 'unixepoch') as created,
  CASE WHEN expiry = 0 THEN 'session' ELSE datetime(expiry, 'unixepoch') END as expiry
FROM moz_cookies
WHERE name LIKE '%token%' 
   OR name LIKE '%session%' 
   OR name LIKE '%auth%'
   OR name LIKE '%key%'
ORDER BY creationTime DESC;
EOF
```

```bash
# Extract cookies for specific domain
sqlite3 cookies.sqlite << 'EOF'
SELECT 
  name,
  value,
  datetime(creationTime/1000000, 'unixepoch') as created,
  datetime(lastAccessed/1000000, 'unixepoch') as accessed
FROM moz_cookies
WHERE host LIKE '%.example.com%'
ORDER BY lastAccessed DESC;
EOF
```

```bash
# Dump all cookies to CSV
sqlite3 -header -csv cookies.sqlite "SELECT * FROM moz_cookies" > cookies.csv
```

---

### permissions.sqlite

**Purpose**: Site-specific permissions granted by user (geolocation, camera, microphone, notifications, etc.).

**Key Tables**:

| Table | Purpose |
|-------|---------|
| `moz_perms` | Permission entries with allow/deny status |
| `moz_hosts` | Legacy host-based permissions |

**Important Fields** (moz_perms):

- `id`: Permission ID
- `origin`: Origin URI (scheme + domain)
- `type`: Permission type (camera, microphone, geolocation, notification, etc.)
- `permission`: Status (1=allow, 2=deny, 3=prompt, 4=allow by default)
- `expireType`: Expiration type (0=permanent, 1=session, 2=expiry-based)
- `expireTime`: Expiration timestamp (milliseconds)
- `modificationTime`: Last change timestamp

**Recovery Commands**:

```bash
# List all permissions
sqlite3 permissions.sqlite << 'EOF'
SELECT 
  origin,
  type,
  CASE 
    WHEN permission = 1 THEN 'Allow'
    WHEN permission = 2 THEN 'Deny'
    WHEN permission = 3 THEN 'Prompt'
    WHEN permission = 4 THEN 'Allow by default'
    ELSE 'Unknown'
  END as status,
  CASE 
    WHEN expireType = 0 THEN 'Permanent'
    WHEN expireType = 1 THEN 'Session'
    WHEN expireType = 2 THEN datetime(expireTime/1000, 'unixepoch')
    ELSE 'Unknown'
  END as expiration,
  datetime(modificationTime/1000, 'unixepoch') as modified
FROM moz_perms
ORDER BY modificationTime DESC;
EOF
```

```bash
# Extract geolocation permissions
sqlite3 permissions.sqlite << 'EOF'
SELECT 
  origin,
  CASE WHEN permission = 1 THEN 'Allow' ELSE 'Deny' END as status,
  datetime(modificationTime/1000, 'unixepoch') as granted
FROM moz_perms
WHERE type = 'geo'
ORDER BY modificationTime DESC;
EOF
```

```bash
# Extract media device permissions
sqlite3 permissions.sqlite << 'EOF'
SELECT 
  origin,
  type,
  CASE WHEN permission = 1 THEN 'Allow' ELSE 'Deny' END as status,
  datetime(modificationTime/1000, 'unixepoch') as granted
FROM moz_perms
WHERE type IN ('camera', 'microphone', 'screen', 'speaker-selection')
ORDER BY modificationTime DESC;
EOF
```

```bash
# Dump all permissions to CSV
sqlite3 -header -csv permissions.sqlite "SELECT * FROM moz_perms" > permissions.csv
```

---

### formhistory.sqlite

**Purpose**: Saved form input history (search terms, text fields, form submissions).

**Key Tables**:

| Table | Purpose |
|-------|---------|
| `moz_formhistory` | Form input history entries |

**Important Fields**:

- `id`: Entry ID
- `fieldname`: HTML form field name
- `value`: Entered text value
- `timesUsed`: Frequency of use
- `firstUsed`: First entry timestamp
- `lastUsed`: Last entry timestamp
- `guid`: Unique identifier

**Forensic Significance**: May contain:
- Search queries (Google, Bing, Wikipedia, etc.)
- Email addresses
- Usernames (before password fields)
- Credit card numbers, addresses, phone numbers (CRITICAL)
- API keys, tokens in form fields

**Recovery Commands**:

```bash
# List all form history entries
sqlite3 formhistory.sqlite << 'EOF'
SELECT 
  fieldname,
  value,
  timesUsed,
  datetime(firstUsed/1000, 'unixepoch') as first_used,
  datetime(lastUsed/1000, 'unixepoch') as last_used
FROM moz_formhistory
ORDER BY lastUsed DESC;
EOF
```

```bash
# Extract potential sensitive data
sqlite3 formhistory.sqlite << 'EOF'
SELECT 
  fieldname,
  value,
  datetime(firstUsed/1000, 'unixepoch') as first_used,
  datetime(lastUsed/1000, 'unixepoch') as last_used
FROM moz_formhistory
WHERE fieldname LIKE '%email%' 
   OR fieldname LIKE '%username%' 
   OR fieldname LIKE '%phone%' 
   OR fieldname LIKE '%address%'
   OR fieldname LIKE '%card%'
ORDER BY lastUsed DESC;
EOF
```

```bash
# Extract search history
sqlite3 formhistory.sqlite << 'EOF'
SELECT 
  value as search_term,
  timesUsed,
  datetime(lastUsed/1000, 'unixepoch') as last_search
FROM moz_formhistory
WHERE fieldname LIKE '%search%' OR fieldname LIKE '%q%'
ORDER BY lastUsed DESC
LIMIT 100;
EOF
```

```bash
# Dump all form history to CSV
sqlite3 -header -csv formhistory.sqlite "SELECT * FROM moz_formhistory" > formhistory.csv
```

---

### storage.sqlite

**Purpose**: DOM storage (localStorage, sessionStorage) and Indexed DB metadata.

**Key Tables**:

| Table | Purpose |
|-------|---------|
| `webappsSession` | Session storage entries |
| `webapps` | Indexed DB and localStorage metadata |

**Important Fields**:

- `origin`: Web application origin
- `key`: Storage key name
- `value`: Stored value (JSON, serialized objects)
- `scope`: Storage type (localStorage=0, sessionStorage=1)

**Forensic Significance**: Applications use DOM storage for:
- Authentication tokens
- User preferences and settings
- Cached API responses
- Application state and history
- Device identifiers

**Recovery Commands**:

```bash
# List all storage origins
sqlite3 storage.sqlite << 'EOF'
SELECT DISTINCT origin FROM webappsSession
UNION
SELECT DISTINCT origin FROM webapps
ORDER BY origin;
EOF
```

```bash
# Extract localStorage entries
sqlite3 storage.sqlite << 'EOF'
SELECT 
  origin,
  key,
  value,
  CASE WHEN scope = 0 THEN 'localStorage' ELSE 'sessionStorage' END as storage_type
FROM webappsSession
WHERE scope = 0
ORDER BY origin;
EOF
```

```bash
# Extract session storage
sqlite3 storage.sqlite << 'EOF'
SELECT 
  origin,
  key,
  value
FROM webappsSession
WHERE scope = 1
ORDER BY origin;
EOF
```

```bash
# Dump all storage to CSV
sqlite3 -header -csv storage.sqlite "SELECT * FROM webappsSession" > storage.csv
```

---

### favicons.sqlite

**Purpose**: Website favicon caching and metadata.

**Key Tables**:

| Table | Purpose |
|-------|---------|
| `moz_favicons` | Favicon entries with data URIs |
| `moz_icons_to_pages` | Mapping of favicons to pages |

**Important Fields**:

- `id`: Favicon ID
- `url`: Favicon URL
- `data`: Icon data (PNG binary)
- `page_url`: Associated page URL
- `expiry`: Cache expiry timestamp

**Forensic Significance**: Can identify visited websites even if history is deleted (via favicon data).

**Recovery Commands**:

```bash
# List favicon history
sqlite3 favicons.sqlite << 'EOF'
SELECT 
  f.url as favicon_url,
  ip.page_url,
  datetime(f.expiry, 'unixepoch') as expires
FROM moz_favicons f
LEFT JOIN moz_icons_to_pages ip ON f.id = ip.icon_id
ORDER BY f.expiry DESC;
EOF
```

```bash
# Extract favicon for specific domain
sqlite3 favicons.sqlite << 'EOF'
SELECT 
  f.url,
  ip.page_url,
  length(f.data) as data_size_bytes
FROM moz_favicons f
JOIN moz_icons_to_pages ip ON f.id = ip.icon_id
WHERE ip.page_url LIKE '%example.com%';
EOF
```

```bash
# Dump all favicon mappings
sqlite3 -header -csv favicons.sqlite "SELECT f.url, ip.page_url FROM moz_favicons f LEFT JOIN moz_icons_to_pages ip ON f.id = ip.icon_id" > favicons.csv
```

---

## JSON Configuration Files: Forensic Extraction

### extensions.json / addons.json

**Purpose**: Installed addon metadata, versions, and permissions.

**Recovery Command**:

```bash
# Extract addon information
cat extensions.json | jq '.addons[] | {
  id: .id,
  name: .name,
  version: .version,
  installDate: .installDate,
  updateDate: .updateDate,
  permissions: .permissions
}' | head -100
```

### search.json

**Recovery Command**:

```bash
# Extract search engine configurations
cat search.json | jq '.engines[] | {
  name: .name,
  url: .urls[0].template
}'
```

### sessionstore.jsonlz4

**Purpose**: Current session state (tabs, windows, form data).

**Recovery Commands**:

```bash
# Decompress sessionstore (requires lz4 binary)
lz4 -d sessionstore.jsonlz4 sessionstore.json

# Extract all open tabs and URLs
cat sessionstore.json | jq '.windows[].tabs[] | {
  url: .entries[-1].url,
  title: .entries[-1].title
}'

# Extract form data
cat sessionstore.json | jq '.windows[].tabs[] | select(.formdata) | .formdata'
```

---

## Batch Analysis: Complete Profile Extraction

### Automated SQLite Extraction Script

```bash
#!/bin/bash

PROFILE_PATH="$HOME/.mozilla/firefox/<profile-name>"
OUTPUT_DIR="./firefox_forensics"
mkdir -p "$OUTPUT_DIR"

# Function to export all tables from a database
export_database() {
    local db="$1"
    local db_name=$(basename "$db" .sqlite)
    
    echo "[*] Processing $db_name..."
    
    # Get list of tables
    tables=$(sqlite3 "$db" ".tables")
    
    for table in $tables; do
        echo "    - Exporting table: $table"
        sqlite3 -header -csv "$db" "SELECT * FROM $table" > "$OUTPUT_DIR/${db_name}_${table}.csv"
    done
}

# Export all SQLite databases
for db in "$PROFILE_PATH"/*.sqlite; do
    [ -f "$db" ] && export_database "$db"
done

# Extract JSON configurations
cp "$PROFILE_PATH/extensions.json" "$OUTPUT_DIR/extensions.json" 2>/dev/null
cp "$PROFILE_PATH/search.json" "$OUTPUT_DIR/search.json" 2>/dev/null
cp "$PROFILE_PATH/prefs.js" "$OUTPUT_DIR/prefs.js" 2>/dev/null

# Decompress sessionstore if present
if [ -f "$PROFILE_PATH/sessionstore.jsonlz4" ]; then
    lz4 -d "$PROFILE_PATH/sessionstore.jsonlz4" "$OUTPUT_DIR/sessionstore.json"
fi

# Decompress bookmark backups
for backup in "$PROFILE_PATH/bookmarkbackups"/*.json.gz; do
    [ -f "$backup" ] && gunzip -c "$backup" > "$OUTPUT_DIR/$(basename "$backup" .gz)"
done

echo "[+] Forensic extraction complete. Output: $OUTPUT_DIR"
```

### Timeline Generation from Multiple Sources

```bash
#!/bin/bash

PROFILE_PATH="$HOME/.mozilla/firefox/<profile-name>"

# Create unified timeline
{
    echo "Timestamp,Event Type,Details"
    
    # History events
    sqlite3 "$PROFILE_PATH/places.sqlite" << 'EOF' | sed 's/^/,history,/' 
SELECT datetime(h.visit_date/1000000, 'unixepoch') || ' | ' || p.url || ' | ' || p.title
FROM moz_historyvisits h
JOIN moz_places p ON h.place_id = p.id
ORDER BY h.visit_date;
EOF
    
    # Cookie creation events
    sqlite3 "$PROFILE_PATH/cookies.sqlite" << 'EOF' | sed 's/^/,cookie_created,/'
SELECT datetime(creationTime/1000000, 'unixepoch') || ' | ' || host || ' | ' || name
FROM moz_cookies
ORDER BY creationTime;
EOF
    
    # Permission grants
    sqlite3 "$PROFILE_PATH/permissions.sqlite" << 'EOF' | sed 's/^/,permission_grant,/'
SELECT datetime(modificationTime/1000, 'unixepoch') || ' | ' || origin || ' | ' || type
FROM moz_perms
WHERE permission = 1
ORDER BY modificationTime;
EOF
    
} | sort > firefox_unified_timeline.csv

echo "[+] Timeline saved to firefox_unified_timeline.csv"
```

---

## Encrypted Data Recovery

### logins.json

**Encryption Method**: Encrypted via NSS (Network Security Services).

**Structure**:
```json
{
  "logins": [
    {
      "id": 1,
      "hostname": "https://example.com",
      "httpRealm": null,
      "formSubmitURL": "https://example.com/login",
      "usernameField": "username",
      "passwordField": "password",
      "encrypted": "base64_encrypted_username|base64_encrypted_password",
      "timeCreated": 1234567890000,
      "timeLastUsed": 1234567890000,
      "timePasswordChanged": 1234567890000,
      "timesUsed": 5
    }
  ],
  "encryptionVersion": 2
}
```

**Recovery**:

```bash
# Copy necessary files for decryption attempt
cp "$PROFILE_PATH/logins.json" .
cp "$PROFILE_PATH/key4.db" . # Or key3.db for older profiles

# Extraction with firefox-decrypt (external tool)
# https://github.com/unode/firefox_decrypt
python3 firefox_decrypt.py . --format csv > logins_decrypted.csv
```

### key4.db / key3.db

**Purpose**: Master password hash and encryption keys.

**Forensic Value**: Critical for credential recovery or evidence of master password protection.

**Recovery Command**:

```bash
# Display key database structure
sqlite3 key4.db ".schema"

# Extraction attempt (requires decryption)
sqlite3 key4.db "SELECT * FROM metadata"
sqlite3 key4.db "SELECT * FROM privkey"
```

---

## Cache Analysis

### cache2/entries/ Directory

**Recovery Command**:

```bash
# Extract all cached resources
find ~/.mozilla/firefox/<profile>/cache2/entries -type f | while read file; do
    # Files are binary; use strings to extract text
    strings "$file" | head -20 > "${file##*/}.txt"
done

# Or use specific tools for HTTP cache analysis
sqlite3 ~/.mozilla/firefox/<profile>/cache2/index.sqlite "SELECT * FROM cache_objects LIMIT 50"
```

### thumbnails/ Directory

**Recovery Command**:

```bash
# List all cached page thumbnails
ls -lah ~/.mozilla/firefox/<profile>/thumbnails/

# Copy for analysis
cp ~/.mozilla/firefox/<profile>/thumbnails/* ./firefox_thumbnails/
```

---

## Common Forensic Queries

### Top 100 Most Visited Sites

```sql
SELECT 
  url,
  visit_count,
  datetime(last_visit_date/1000000, 'unixepoch') as last_visit
FROM moz_places
WHERE url NOT LIKE 'about:%' AND url NOT LIKE 'file:%'
ORDER BY visit_count DESC
LIMIT 100;
```

### Sites Visited in Last 24 Hours

```sql
SELECT 
  p.url,
  p.title,
  datetime(h.visit_date/1000000, 'unixepoch') as visit_time,
  CASE WHEN h.visit_type = 2 THEN 'Typed' ELSE 'Clicked' END as method
FROM moz_historyvisits h
JOIN moz_places p ON h.place_id = p.id
WHERE h.visit_date > (strftime('%s', 'now') - 86400) * 1000000
ORDER BY h.visit_date DESC;
```

### Download History Reconstruction

```sql
SELECT DISTINCT
  url,
  title,
  datetime(last_visit_date/1000000, 'unixepoch') as last_accessed
FROM moz_places
WHERE title LIKE '%download%' 
   OR title LIKE '%file%'
   OR url LIKE '%download%'
ORDER BY last_visit_date DESC;
```

### Email Address Recovery from Form History

```sql
SELECT DISTINCT
  value as email_address,
  timesUsed,
  datetime(lastUsed/1000, 'unixepoch') as last_used
FROM moz_formhistory
WHERE value LIKE '%@%.%' AND LENGTH(value) < 100
ORDER BY lastUsed DESC;
```

### Active Authentication Sessions

```sql
SELECT 
  host,
  name,
  datetime(creationTime/1000000, 'unixepoch') as created,
  CASE WHEN expiry = 0 THEN 'Session' ELSE datetime(expiry, 'unixepoch') END as expires
FROM moz_cookies
WHERE isHttpOnly = 1 AND (
  name LIKE '%token%' OR 
  name LIKE '%auth%' OR 
  name LIKE '%session%' OR
  name LIKE '%jwt%'
)
ORDER BY creationTime DESC;
```

### Referrer Chain Analysis

```sql
WITH RECURSIVE referrer_chain AS (
  SELECT 
    h.id,
    p.url,
    p.title,
    h.visit_date,
    h.from_visit,
    1 as depth
  FROM moz_historyvisits h
  JOIN moz_places p ON h.place_id = p.id
  WHERE h.from_visit IS NOT NULL
  
  UNION ALL
  
  SELECT 
    h.id,
    p.url,
    p.title,
    h.visit_date,
    h.from_visit,
    rc.depth + 1
  FROM referrer_chain rc
  JOIN moz_historyvisits h ON rc.from_visit = h.id
  JOIN moz_places p ON h.place_id = p.id
  WHERE rc.depth < 10
)
SELECT * FROM referrer_chain
ORDER BY visit_date DESC, depth
LIMIT 1000;
```

### Geolocation Access Timeline

```sql
SELECT 
  origin,
  CASE WHEN permission = 1 THEN 'Granted' ELSE 'Denied' END as status,
  datetime(modificationTime/1000, 'unixepoch') as when_modified,
  CASE WHEN expireType = 1 THEN 'Session' 
       WHEN expireType = 2 THEN datetime(expireTime/1000, 'unixepoch')
       ELSE 'Permanent'
  END as expiration
FROM permissions.moz_perms
WHERE type = 'geo'
ORDER BY modificationTime DESC;
```

---

## Hash and Integrity Verification

```bash
# Generate SHA-256 hashes of all relevant files
find ~/.mozilla/firefox/<profile> -type f \(
    -name "*.sqlite" -o 
    -name "*.json" -o 
    -name "prefs.js"
\) -exec sha256sum {} \; > firefox_profile_hashes.txt

# Verify integrity
sha256sum -c firefox_profile_hashes.txt

# Generate file listing with metadata
find ~/.mozilla/firefox/<profile> -type f -exec ls -lh {} \; | awk '{print $9, $5, $6, $7, $8}' > firefox_file_manifest.txt
```

---

## Notes on Encryption and Recovery

- **Master Password**: If set, blocks access to saved credentials in logins.json
- **DPAPI (Windows)**: Credentials may be encrypted via Windows Data Protection API
- **Ransomware Indicators**: Check modification times for suspicious bulk changes
- **Deleted Data**: Use filesystem recovery tools (carving) to recover deleted SQLite journals
- **Profile Locks**: Active profiles may have lock files; copy profile while browser closed

---

## Evidence Collection Checklist

- [ ] Copy entire profile directory (maintain timestamps, ACLs)
- [ ] Verify SHA-256 hashes of all files
- [ ] Export all SQLite databases to CSV
- [ ] Decompress JSON files (sessionstore, bookmarks)
- [ ] Extract extensions and addon metadata
- [ ] Recover favicons database
- [ ] Document any locked/in-use files
- [ ] Check for deleted files in filesystem free space
- [ ] Generate unified timeline
- [ ] Analyze cache contents
- [ ] Identify encrypted credentials (logins.json)
- [ ] Document all third-party extensions and their functionality

