"""Constants used throughout the WPT scanner."""

# Request settings
DEFAULT_TIMEOUT = 10
DEFAULT_THREADS = 5
DEFAULT_USER_AGENT = "Mozilla/5.0 (Linux Security Scanner) WPT/2.0"

# SSL/TLS settings
SSL_PORT = 443
RECOMMENDED_TLS_VERSION = "TLSv1.3"
WEAK_CIPHERS = ["NULL", "RC4", "DES", "MD5", "EXPORT"]

# Common subdomains for enumeration
COMMON_SUBDOMAINS = [
    "www",
    "mail",
    "remote",
    "blog",
    "webmail",
    "server",
    "ns1",
    "ns2",
    "smtp",
    "secure",
    "vpn",
    "api",
    "ftp",
    "admin",
    "portal",
    "test",
    "staging",
    "dev",
    "prod",
]

# DNS record types
DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]

# Common API paths
COMMON_API_PATHS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/rest",
    "/rest/v1",
    "/rest/v2",
    "/graphql",
    "/v1",
    "/v2",
]

# HTTP methods to test
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]

# WAF signatures
WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "__cfduid", "cf-cache-status", "cloudflare"],
    "AWS WAF": ["x-amzn-RequestId", "x-amz-cf-id", "x-amz-apigw-id"],
    "Akamai": ["akamai-origin-hop", "akamaighost"],
    "Imperva": ["incap_ses_", "visid_incap_", "incap"],
    "F5 BIG-IP": ["BigIP", "F5-TrafficShield", "X-WA-Info"],
    "Sucuri": ["x-sucuri-id", "sucuri"],
    "ModSecurity": ["mod_security", "NOYB"],
}

# JavaScript vulnerability patterns
JS_VULN_PATTERNS = {
    "Hardcoded Credentials": r'(?i)(password|apikey|api_key|secret|token|auth)\s*[=:]\s*["\'][^"\']+["\']',
    "Unsafe DOM": r"(?i)(innerHTML|outerHTML|document\.write|document\.writeln)",
    "Eval Usage": r"(?i)eval\s*\(",
    "Possible XSS": r"(?i)(location\.href|location\.hash|location\.search|window\.location)",
    "Data Exposure": r"(?i)(console\.log|console\.debug|console\.info|alert)\s*\(",
    "Unsafe Deserialization": r"(?i)(JSON\.parse|eval|Function)\s*\(",
}

# Security headers
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

# Output formats
OUTPUT_FORMATS = ["txt", "json", "html", "csv"]
