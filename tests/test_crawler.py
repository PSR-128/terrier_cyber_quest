import pytest
from backend.crawler.scope import ScopeController
from backend.crawler.crawler import WebCrawler, DiscoveredEndpoint

def test_scope_controller():
    scope = ScopeController(
        target_url="http://127.0.0.1:5000",
        allowed_domains=["127.0.0.1", "localhost"],
        allow_subdomains=True,
        max_depth=2
    )

    assert scope.is_in_scope("http://127.0.0.1:5000/search?q=test") is True
    assert scope.is_in_scope("http://localhost:5000/greet") is True
    assert scope.is_in_scope("https://evil.com/malicious") is False
    assert "evil.com" in scope.get_intercepted_external_domains()

def test_discovered_endpoint_model():
    ep = DiscoveredEndpoint(
        url="http://127.0.0.1:5000/search",
        method="GET",
        params=[{"name": "q", "type": "query"}],
        headers={"Content-Type": "text/html"}
    )
    d = ep.to_dict()
    assert d["url"] == "http://127.0.0.1:5000/search"
    assert d["method"] == "GET"
    assert len(d["params"]) == 1
