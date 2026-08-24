"""
Autonomous Web Crawler & Surface Discovery Engine.
Discovers endpoints, parameters, HTML forms, query parameters, client-side scripts, and API routes.
Features strict URL normalization and loop/duplicate prevention.
"""

import re
import time
import asyncio
import httpx
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from typing import List, Dict, Any, Set, Optional, Callable
from backend.crawler.scope import ScopeController, normalize_url


class DiscoveredEndpoint:
    def __init__(
        self,
        url: str,
        method: str = "GET",
        params: Optional[List[Dict[str, Any]]] = None,
        headers: Optional[Dict[str, str]] = None,
        body_template: Optional[Dict[str, Any]] = None,
        discovered_via: str = "crawl",
        raw_html: Optional[str] = None
    ):
        self.url = normalize_url(url) or url
        self.method = method.upper()
        self.params = params or []
        self.headers = headers or {}
        self.body_template = body_template or {}
        self.discovered_via = discovered_via
        self.raw_html = raw_html

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "params": self.params,
            "headers": self.headers,
            "body_template": self.body_template,
            "discovered_via": self.discovered_via
        }


class WebCrawler:
    def __init__(
        self,
        scope: ScopeController,
        auth_headers: Optional[Dict[str, str]] = None,
        auth_cookies: Optional[Dict[str, str]] = None,
        on_progress: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        stop_checker: Optional[Callable[[], bool]] = None
    ):
        self.scope = scope
        self.auth_headers = auth_headers or {}
        self.auth_cookies = auth_cookies or {}
        self.on_progress = on_progress
        self.stop_checker = stop_checker
        self.visited_urls: Set[str] = set()
        self.queued_urls: Set[str] = set()
        self.discovered_endpoints: List[DiscoveredEndpoint] = []
        self.discovered_scripts: List[Dict[str, Any]] = []

    def _emit(self, event_type: str, data: Dict[str, Any]):
        if self.on_progress:
            try:
                self.on_progress(event_type, data)
            except Exception:
                pass

    def _enqueue_url(self, queue: List[tuple[str, int]], raw_url: str, base_url: str, depth: int):
        """Normalize URL, verify scope, and enqueue if not previously visited or queued."""
        if depth > self.scope.max_depth:
            return

        joined = urljoin(base_url, raw_url)
        norm = normalize_url(joined)
        if not norm:
            return

        if norm in self.visited_urls or norm in self.queued_urls:
            return

        if not self.scope.is_in_scope(norm):
            return

        self.queued_urls.add(norm)
        queue.append((norm, depth))

    async def crawl(self) -> List[DiscoveredEndpoint]:
        """
        Execute BFS autonomous crawling within scope boundaries.
        Guarantees no URL is visited more than once.
        """
        start_url = normalize_url(self.scope.target_url)
        queue: List[tuple[str, int]] = [(start_url, 0)]
        self.queued_urls.add(start_url)
        start_time = time.time()

        headers = {
            "User-Agent": "TerrierCyberQuest-Scanner/2.0 (Authorized Security Audit Engine; Safe)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            **self.auth_headers
        }

        async with httpx.AsyncClient(
            headers=headers,
            cookies=self.auth_cookies,
            timeout=10.0,
            verify=False,
            follow_redirects=False
        ) as client:
            while queue and len(self.visited_urls) < self.scope.max_pages:
                if self.stop_checker and self.stop_checker():
                    self._emit("log", {"message": "Crawl terminated by user request."})
                    break

                if (time.time() - start_time) > self.scope.max_duration_sec:
                    self._emit("log", {"message": "Crawl duration limit reached."})
                    break

                current_url, depth = queue.pop(0)
                norm_current_url = normalize_url(current_url)

                if norm_current_url in self.visited_urls:
                    continue

                if not self.scope.is_in_scope(norm_current_url):
                    continue

                self.visited_urls.add(norm_current_url)
                self._emit("crawl_page", {
                    "url": norm_current_url,
                    "depth": depth,
                    "visited_count": len(self.visited_urls),
                    "queue_size": len(queue)
                })

                try:
                    response = await client.get(norm_current_url)
                    
                    # Handle redirects within scope
                    if response.is_redirect:
                        redirect_target = response.headers.get("location")
                        if redirect_target:
                            self._enqueue_url(queue, redirect_target, norm_current_url, depth)

                    # Extract query parameters from URL itself
                    parsed_u = urlparse(norm_current_url)
                    query_params = parse_qs(parsed_u.query)
                    param_list = [{"name": k, "type": "query", "sample_value": v[0] if v else ""} for k, v in query_params.items()]

                    endpoint = DiscoveredEndpoint(
                        url=norm_current_url,
                        method="GET",
                        params=param_list,
                        headers=dict(response.headers),
                        discovered_via="url_crawl",
                        raw_html=response.text if "text/html" in response.headers.get("content-type", "") else None
                    )
                    self.discovered_endpoints.append(endpoint)

                    # If HTML response, parse DOM
                    content_type = response.headers.get("content-type", "")
                    if "text/html" in content_type:
                        html_content = response.text
                        soup = BeautifulSoup(html_content, "html.parser")

                        # 1. Discover Links (anchor tags)
                        if depth < self.scope.max_depth:
                            for a_tag in soup.find_all("a", href=True):
                                href = a_tag["href"]
                                self._enqueue_url(queue, href, norm_current_url, depth + 1)

                        # 2. Discover Forms
                        for form in soup.find_all("form"):
                            action = form.get("action", "")
                            form_url = normalize_url(urljoin(norm_current_url, action)) if action else norm_current_url
                            form_method = form.get("method", "GET").upper()
                            
                            form_params = []
                            for input_tag in form.find_all(["input", "textarea", "select"]):
                                name = input_tag.get("name")
                                if not name:
                                    continue
                                input_type = input_tag.get("type", "text")
                                val = input_tag.get("value", "")
                                form_params.append({
                                    "name": name,
                                    "type": input_type,
                                    "sample_value": val
                                })

                            form_endpoint = DiscoveredEndpoint(
                                url=form_url,
                                method=form_method,
                                params=form_params,
                                headers={},
                                discovered_via="html_form"
                            )
                            self.discovered_endpoints.append(form_endpoint)

                        # 3. Discover Script routes and JS files
                        for script in soup.find_all("script"):
                            src = script.get("src")
                            if src:
                                js_url = normalize_url(urljoin(norm_current_url, src))
                                if self.scope.is_in_scope(js_url):
                                    self.discovered_scripts.append({"url": js_url, "type": "external"})
                            else:
                                if script.string:
                                    self.discovered_scripts.append({
                                        "url": norm_current_url,
                                        "type": "inline",
                                        "content": script.string
                                    })
                                    # Regex search for api endpoints in inline JS
                                    found_endpoints = re.findall(r'[\'"`](/api/[^\'"`]+|/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+)[\'"`]', script.string)
                                    for ep in found_endpoints:
                                        self._enqueue_url(queue, ep, norm_current_url, depth + 1)

                except Exception as ex:
                    self._emit("crawl_error", {"url": norm_current_url, "error": str(ex)})

        # Determine crawl completion reason
        if self.stop_checker and self.stop_checker():
            crawl_reason = "stopped"
        elif (time.time() - start_time) > self.scope.max_duration_sec:
            crawl_reason = "duration_limit"
        elif len(self.visited_urls) >= self.scope.max_pages and queue:
            crawl_reason = "page_limit"
        elif not queue:
            crawl_reason = "exhausted"
        else:
            crawl_reason = "unknown"

        self._emit("crawl_completed", {
            "reason": crawl_reason,
            "pages_visited": len(self.visited_urls),
            "pages_limited": self.scope.pages_limited,
            "depth_limited": self.scope.depth_limited,
            "queue_remaining": len(queue)
        })

        # Deduplicate endpoints deterministically by normalized URL, method, and param keys
        unique_map = {}
        for ep in self.discovered_endpoints:
            norm_u = normalize_url(ep.url)
            key = (norm_u, ep.method, tuple(sorted(p["name"] for p in ep.params)))
            if key not in unique_map:
                ep.url = norm_u
                unique_map[key] = ep

        return list(unique_map.values())
