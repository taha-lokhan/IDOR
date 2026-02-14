# ============================================
# IDOR SCANNER - ALL COMMANDS LIST
# ============================================

# Help and Version
idor --help
idor --version

# Basic Scan
idor scan https://api.example.com/users/{id} --id-range 1 100

# Scan with Authentication
idor scan https://api.example.com/users/{id} --id-range 1 100 --header "Authorization: Bearer TOKEN"

# Scan with Short Flag
idor scan https://api.example.com/users/{id} --id-range 1 100 -H "Authorization: Bearer TOKEN"

# Scan with Multiple Headers
idor scan https://api.example.com/users/{id} --id-range 1 100 -H "Authorization: Bearer TOKEN" -H "X-API-Key: KEY123"

# Scan with Custom Concurrency
idor scan https://api.example.com/users/{id} --id-range 1 100 --concurrency 10
idor scan https://api.example.com/users/{id} --id-range 1 100 -c 10

# Scan with Cookie
idor scan https://api.example.com/users/{id} --id-range 1 100 -H "Cookie: session=abc123"

# Scan with Basic Auth
idor scan https://api.example.com/users/{id} --id-range 1 100 -H "Authorization: Basic dXNlcjpwYXNz"

# Scan with API Key
idor scan https://api.example.com/users/{id} --id-range 1 100 -H "X-API-Key: your-key-here"

# Config-based Scan
idor scan-config config.yaml

# Open Dashboard
idor dashboard

# Scan Help
idor scan --help

# Config Scan Help
idor scan-config --help

# With Burp Proxy
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080
idor scan https://api.example.com/users/{id} --id-range 1 100
unset http_proxy https_proxy

# With ZAP Proxy
export http_proxy=http://127.0.0.1:8090
export https_proxy=http://127.0.0.1:8090
idor scan https://api.example.com/users/{id} --id-range 1 100
unset http_proxy https_proxy

# Chain Commands
idor scan https://api.example.com/users/{id} --id-range 1 100 && idor dashboard

# Different Endpoint Types
idor scan https://api.example.com/users/{id} --id-range 1 100
idor scan https://api.example.com/posts/{id} --id-range 1 500
idor scan https://api.example.com/orders/{id} --id-range 1000 2000
idor scan https://cdn.example.com/files/{id} --id-range 1 500
idor scan https://billing.example.com/invoices/{id} --id-range 10000 11000

# Performance Variations
idor scan https://api.example.com/users/{id} --id-range 1 500 -c 1    # Slow/Stealthy
idor scan https://api.example.com/users/{id} --id-range 1 1000 -c 5   # Balanced
idor scan https://api.example.com/users/{id} --id-range 1 5000 -c 15  # Fast/Aggressive

# View Reports
ls -la reports/
cat reports/scan_20260214_123045.txt
cat reports/scan_20260214_123045.json
open reports/scan_20260214_123045.html        # macOS
xdg-open reports/scan_20260214_123045.html    # Linux
