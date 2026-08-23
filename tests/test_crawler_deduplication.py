import pytest
from backend.crawler.scope import normalize_url, ScopeController

def test_normalize_url_trailing_slashes_and_fragments():
    u1 = "http://127.0.0.1:5000/search/"
    u2 = "http://127.0.0.1:5000/search#section1"
    u3 = "HTTP://127.0.0.1:5000/search"
    u4 = "http://127.0.0.1:5000//search"
    
    assert normalize_url(u1) == "http://127.0.0.1:5000/search"
    assert normalize_url(u2) == "http://127.0.0.1:5000/search"
    assert normalize_url(u3) == "http://127.0.0.1:5000/search"
    assert normalize_url(u4) == "http://127.0.0.1:5000/search"

def test_normalize_url_query_parameter_sorting():
    q1 = "http://example.com/items?b=2&a=1"
    q2 = "http://example.com/items?a=1&b=2"
    assert normalize_url(q1) == normalize_url(q2)

def test_normalize_url_default_ports():
    p1 = "http://example.com:80/path"
    p2 = "https://example.com:443/path"
    assert normalize_url(p1) == "http://example.com/path"
    assert normalize_url(p2) == "https://example.com/path"

def test_scope_controller_with_normalized_urls():
    scope = ScopeController("http://127.0.0.1:5000/")
    assert scope.is_in_scope("http://127.0.0.1:5000/api/users")
    assert scope.is_in_scope("http://127.0.0.1:5000/search#tag")
    assert not scope.is_in_scope("http://evil.com/leak")
