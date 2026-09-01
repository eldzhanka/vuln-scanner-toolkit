"""
Endpoint discovery module.

Brute-forces common paths and filenames against a base URL to surface
endpoints that aren't linked from the site's normal navigation — admin
panels, backup files, config files, API routes, etc. Uses a small
built-in wordlist by default; pass --wordlist for something bigger
(e.g. SecLists' raft or common.txt).
"""

from core.http_client import HTTPClient
from core.report import Report

DEFAULT_PATHS = [
    # Admin / auth panels
    "admin", "admin/", "administrator", "admin/login", "admin/login.php",
    "login", "login.php", "signin", "wp-admin", "wp-login.php",
    "user/login", "manage", "management", "cpanel", "portal",
    "dashboard", "controlpanel", "adminpanel", "moderator",

    # API / docs
    "api", "api/", "api/v1", "api/v2", "api/v3", "graphql", "graphiql",
    "swagger", "swagger.json", "swagger-ui.html", "swagger/index.html",
    "openapi.json", "api-docs", "api/swagger.json", "redoc",

    # Backups / archives
    "backup", "backup/", "backups", "backup.zip", "backup.tar.gz",
    "backup.sql", "db_backup.sql", "database.sql", "dump.sql",
    "site.zip", "www.zip", "old", "old/", "old_site", "archive",

    # Config / secrets
    "config", "config.php", "config.json", "config.yml", "config.yaml",
    "settings.json", "settings.py", "appsettings.json", "web.config",
    ".env", ".env.local", ".env.production", ".env.backup",
    "secrets.json", "credentials.json", "wp-config.php",

    # Version control / CI
    ".git/HEAD", ".git/config", ".git/logs/HEAD", ".gitignore",
    ".svn/entries", ".hg/hgrc", ".dockerignore", "Dockerfile",
    "docker-compose.yml", ".github/workflows",

    # Web server / meta
    ".htaccess", ".htpasswd", "robots.txt", "sitemap.xml", "humans.txt",
    "crossdomain.xml", "web.xml", "nginx.conf", "httpd.conf",

    # Debug / dev / test
    "test", "test.php", "test/", "debug", "debug.php", "dev", "dev/",
    "staging", "staging/", "beta", "phpinfo.php", "info.php",
    "server-status", "server-info", "trace.axd", "elmah.axd",

    # Framework / actuator / health endpoints
    "actuator", "actuator/health", "actuator/env", "actuator/beans",
    "health", "healthz", "status", "metrics", "debug/vars",
    ".well-known/security.txt", "console", "shell", "cmd",

    # Uploads / files / storage
    "uploads", "upload", "files", "file", "assets", "static",
    "media", "images", "tmp", "temp", "storage", "public",

    # Common CMS
    "wp-content", "wp-includes", "wp-json", "xmlrpc.php",
    "sites/default/files", "misc/drupal.js", "index.php/admin",

    # Logs
    "logs", "log", "error.log", "access.log", "debug.log",
]

# Extra file-extension probes appended for each "interesting" base word,
# useful for spotting stray config/backup files a full wordlist would miss.
BACKUP_EXTENSIONS = [".bak", ".old", ".swp", ".orig", "~"]

# Statuses worth reporting — 200 means it's there and served, 301/302
# often mean a redirect to a login page (still confirms the path
# exists), 403 confirms existence but access is blocked.
INTERESTING_STATUSES = {200, 301, 302, 401, 403}


def run(args, client: HTTPClient):
    report = Report("endpoint-discovery")
    paths = list(args.paths or DEFAULT_PATHS)

    if args.extensions:
        # For each base path, also try it with common backup/leftover
        # extensions appended,catches things like config.php.bak
        # that a plain wordlist run would miss.
        extra = []
        for path in paths:
            for ext in BACKUP_EXTENSIONS:
                extra.append(f"{path}{ext}")
        paths.extend(extra)

    base_url = args.url.rstrip("/")

    print(f"[*] Scan start: {base_url}")
    print(f"[*] Paths to try: {len(paths)}\n")

    for path in paths:
        target_url = f"{base_url}/{path.lstrip('/')}"
        response = client.get(target_url)
        if response is None:
            continue

        if response.status_code in INTERESTING_STATUSES:
            report.add_finding(
                path=path,
                url=response.url,
                status=response.status_code,
                length=len(response.text),
            )

    report.summarize()
    return report
