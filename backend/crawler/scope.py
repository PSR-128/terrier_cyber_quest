import re
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
from typing import Set, List, Dict, Any, Optional


def normalize_url(url: str) -> str:
    """
    Strict URL normalization to prevent crawler loops and duplicate crawling:
    - Lowercases scheme and netloc
    - Strips default HTTP/HTTPS ports (:80, :443)
    - Resolves and cleans path (removes redundant // slashes, normalizes trailing slash)
    - Strips URL fragments (#...)
    - Deterministically sorts query parameters so ?b=2&a=1 matches ?a=1&b=2
    """
    if not url or not isinstance(url, str):
        return ""

    url = url.strip()
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    # Strip default ports
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]

    # Clean path (collapse multiple slashes, strip trailing slash unless root)
    path = re.sub(r'/+', '/', parsed.path or "/")
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    # Sort query parameters
    query_params = parse_qsl(parsed.query, keep_blank_values=True)
    sorted_query = urlencode(sorted(query_params))

    # Strip fragment completely
    normalized = urlunparse((scheme, netloc, path, parsed.params, sorted_query, ""))
    return normalized


class ScopeController:
    def __init__(
        self,
        target_url: str,
        allowed_domains: Optional[List[str]] = None,
        allow_subdomains: bool = True,
        max_depth: int = 0,
        max_pages: int = 0,
        max_duration_sec: int = 600
    ):
        self.target_url = normalize_url(target_url)
        parsed = urlparse(self.target_url)
        self.base_domain = parsed.netloc.split(':')[0].lower()
        self.base_scheme = parsed.scheme.lower()
        
        self.allowed_domains: Set[str] = set()
        if allowed_domains:
            for d in allowed_domains:
                self.allowed_domains.add(d.lower())
        else:
            self.allowed_domains.add(self.base_domain)
            
        self.allow_subdomains = allow_subdomains

        # Interpret 0 as unlimited — use high sentinel values internally
        self.depth_limited = max_depth > 0
        self.pages_limited = max_pages > 0
        self.max_depth = max_depth if max_depth > 0 else 999
        self.max_pages = max_pages if max_pages > 0 else 100000

        self.max_duration_sec = max_duration_sec
        self.external_links_intercepted: Set[str] = set()

    def is_in_scope(self, url: str) -> bool:
        """Verify whether an extracted URL is authorized for scanning."""
        if not url:
            return False
            
        parsed = urlparse(url)
        # Only accept http and https
        if parsed.scheme.lower() not in ('http', 'https'):
            return False
            
        domain = parsed.netloc.split(':')[0].lower()
        if not domain:
            return False
            
        # Exact match check
        if domain in self.allowed_domains:
            return True
            
        # Subdomain check
        if self.allow_subdomains:
            for allowed in self.allowed_domains:
                if domain.endswith("." + allowed):
                    return True
                    
        # Outside scope
        self.external_links_intercepted.add(domain)
        return False

    def get_intercepted_external_domains(self) -> List[str]:
        return sorted(list(self.external_links_intercepted))
