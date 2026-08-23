"""
Pydantic Schemas for API Requests and Responses.
"""

from pydantic import BaseModel, Field, HttpUrl
from typing import List, Dict, Any, Optional


class ScopeConfigSchema(BaseModel):
    allowed_domains: Optional[List[str]] = None
    allow_subdomains: bool = True
    max_depth: int = Field(default=3, ge=1, le=10)
    max_pages: int = Field(default=30, ge=1, le=200)
    max_duration_sec: int = Field(default=180, ge=10, le=1200)


class AuthConfigSchema(BaseModel):
    bearer_token: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    cookies: Optional[Dict[str, str]] = None
    gemini_api_key: Optional[str] = None


class StartScanRequest(BaseModel):
    target_url: str
    scope: Optional[ScopeConfigSchema] = None
    auth: Optional[AuthConfigSchema] = None


class PatchGenerateRequest(BaseModel):
    scan_id: str
    finding_id: str
    target_file: str
    vuln_type: str
    parameter: Optional[str] = None


class PatchApplyRequest(BaseModel):
    scan_id: str
    finding_id: str
    target_file: str
    patched_code: str


class RegressionVerifyRequest(BaseModel):
    scan_id: str
    finding_id: str
    endpoint_url: str
    http_method: str = "GET"
    parameter: Optional[str] = None
