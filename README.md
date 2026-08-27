# vuln-scanner-toolkit

A modular command-line toolkit for testing web applications for common vulnerability classes. Built around a shared HTTP client and reporting layer, so each vulnerability check is a self-contained module that plugs into the same CLI.

Started as a single path traversal scanner, restructured into a toolkit so new checks (XSS, JWT issues, IDOR, endpoint discovery, and more) can be added as modules without rewriting the request-handling or output logic each time.

## Why a toolkit instead of separate scripts

Most small security scripts duplicate the same plumbing — sending requests, handling headers/cookies, printing results. This project centralizes that into `core/`, so every module is just the vulnerability-specific logic: what payloads to try, what to look for in the response.

## Project structure

```
vuln-scanner-toolkit/
├── main.py                  # CLI entry point — routes to the selected module
├── core/
│   ├── http_client.py       # Shared HTTP client (headers, cookies, proxy, pacing)
│   └── report.py            # Shared results reporting (console output + JSON export)
├── modules/
│   └── path_traversal.py    # Path traversal scanner (first module, more to come)
├── payloads/                # Optional custom payload wordlists
├── requirements.txt
└── LICENSE
```

## Features

- **Modular design** — each vulnerability class is its own module under `modules/`, sharing a common HTTP client and report format
- **Polite by default** — requests are automatically paced (small delay between requests), and the client backs off on its own if the target responds with `429 Too Many Requests`. This isn't a flag you have to remember to set — it's built into the shared client, so every module behaves reasonably out of the box, including against real bug bounty scope where hammering a target is against most programs' rules.
- **Burp Suite proxy support** — route traffic through Burp for inspection with `--proxy`
- **Custom wordlists, headers, and cookies** — test authenticated endpoints and swap in your own payload lists
- **JSON export** — save results with `-o results.json` for later reference or reporting

## Requirements

```bash
pip install -r requirements.txt
```

## Usage

### Path traversal scan

```bash
python3 main.py path-traversal -u http://example.com/view -p filename
```

With a custom wordlist:

```bash
python3 main.py path-traversal -u http://example.com/view -p filename -w payloads/my_list.txt
```

Behind authentication:

```bash
python3 main.py path-traversal -u http://example.com/view -p filename -c "session=abc123; role=user"
```

Through Burp Suite (for inspecting traffic):

```bash
python3 main.py path-traversal -u http://example.com/view -p filename --proxy http://127.0.0.1:8080
```

Targeting Windows, saving results:

```bash
python3 main.py path-traversal -u http://example.com/view -p filename --os windows -o results.json
```

### Common flags (shared across all modules)

| Flag | Description |
|---|---|
| `-u`, `--url` | Target URL |
| `-c`, `--cookie` | Session cookie string, e.g. `"session=abc123; role=user"` |
| `-H`, `--header` | Custom header, e.g. `"Authorization: Bearer xyz"`. Repeatable |
| `--proxy` | Proxy URL, e.g. `http://127.0.0.1:8080` (for Burp Suite) |
| `--timeout` | Per-request timeout in seconds (default: `5`) |
| `--insecure` | Disable SSL certificate verification |
| `-o`, `--output` | Save results to a JSON file |

### `path-traversal` module flags

| Flag | Description |
|---|---|
| `-p`, `--param` | Parameter name to test (required) |
| `-m`, `--method` | HTTP method: `GET` or `POST` (default: `GET`) |
| `-w`, `--wordlist` | Path to a custom payload wordlist file |
| `--os` | Target OS for success markers: `linux`, `windows`, or `all` |

## Adding a new module

Each module implements a `run(args, client)` function and reports findings through the shared `Report` class. `modules/path_traversal.py` is the reference implementation — a new module (XSS, JWT, IDOR, etc.) follows the same shape and registers its own subcommand and flags in `main.py`.

## Roadmap

- [x] Path traversal module
- [x] Burp Suite proxy support
- [x] Polite-by-default request pacing and rate-limit backoff
- [x] XSS module
- [ ] JWT analysis module (alg confusion, weak secrets, etc.)
- [ ] IDOR checker module
- [ ] API endpoint discovery module

## Disclaimer

This tool is intended for authorized security testing only. Use it against systems you own or have explicit permission to test — including staying within the scope and rules of any bug bounty program you use it in.

## License

MIT — see [LICENSE](LICENSE).
