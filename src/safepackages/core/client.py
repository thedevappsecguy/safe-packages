import httpx
import asyncio
import logging
from typing import List, Optional, Dict, Any
from .models import (
    V1Query,
    V1BatchQuery,
    V1VulnerabilityList,
    V1BatchVulnerabilityList,
    OsvVulnerability,
    OsvPackage,
)

logger = logging.getLogger(__name__)


class OSVClient:
    def __init__(
        self,
        base_url: str = "https://api.osv.dev",
        timeout: float = 30.0,
        max_retries: int = 3,
        initial_retry_delay: float = 1.0,
        enable_retry: bool = True,
        enable_pagination: bool = True,
        max_pages: int = 100,
    ):
        self.base_url = base_url
        self.timeout = timeout
        self.max_retries = max_retries
        self.initial_retry_delay = initial_retry_delay
        self.enable_retry = enable_retry
        self.enable_pagination = enable_pagination
        self.max_pages = max_pages
        self.client = httpx.AsyncClient(
            base_url=base_url,
            timeout=timeout,
            headers={"Content-Type": "application/json"},
        )

    async def close(self):
        await self.client.aclose()

    async def _request(
        self, method: str, path: str, json_data: Optional[Dict[str, Any]] = None
    ) -> httpx.Response:
        url = path
        max_attempts = self.max_retries + 1 if self.enable_retry else 1

        for attempt in range(max_attempts):
            try:
                response = await self.client.request(method, url, json=json_data)

                if response.status_code == 429 or (500 <= response.status_code < 600):
                    if attempt < max_attempts - 1:
                        delay = self.initial_retry_delay * (2**attempt)
                        retry_after = response.headers.get("Retry-After")
                        if retry_after:
                            try:
                                delay = float(retry_after)
                            except ValueError:
                                pass
                        logger.warning(
                            f"Request failed with {response.status_code}, retrying in {delay}s..."
                        )
                        await asyncio.sleep(delay)
                        continue

                response.raise_for_status()
                return response

            except (httpx.RequestError, httpx.HTTPStatusError) as e:
                if isinstance(e, httpx.HTTPStatusError) and not (
                    e.response.status_code == 429 or 500 <= e.response.status_code < 600
                ):
                    raise e

                if attempt < max_attempts - 1:
                    delay = self.initial_retry_delay * (2**attempt)
                    logger.warning(f"Request failed with {e}, retrying in {delay}s...")
                    await asyncio.sleep(delay)
                    continue
                raise e

        raise httpx.RequestError("Max retries exceeded")

    async def query(self, query: V1Query) -> V1VulnerabilityList:
        if not self.enable_pagination:
            return await self._query_single(query)

        all_vulns: List[OsvVulnerability] = []
        current_page_token = query.pageToken
        page_count = 0

        while page_count < self.max_pages:
            page_count += 1

            # Create a copy of the query with the current page token
            current_query = query.model_copy(update={"pageToken": current_page_token})

            response = await self._query_single(current_query)

            if response.vulns:
                all_vulns.extend(response.vulns)

            if not response.nextPageToken:
                break

            current_page_token = response.nextPageToken

        return V1VulnerabilityList(vulns=all_vulns if all_vulns else None)

    async def _query_single(self, query: V1Query) -> V1VulnerabilityList:
        # Exclude None fields to match API expectations
        json_data = query.model_dump(exclude_none=True, by_alias=True)
        # Manually handle pageToken -> page_token mapping if needed, but Pydantic by_alias should work if defined.
        # Wait, the swagger defines `pageToken` but the TS client sends `pageToken`.
        # The TS client maps `page_token` (internal) to `pageToken` (API).
        # My model uses `pageToken` directly.

        response = await self._request("POST", "/v1/query", json_data=json_data)
        return V1VulnerabilityList.model_validate(response.json())

    async def query_batch(self, batch_query: V1BatchQuery) -> V1BatchVulnerabilityList:
        json_data = batch_query.model_dump(exclude_none=True, by_alias=True)
        response = await self._request("POST", "/v1/querybatch", json_data=json_data)
        return V1BatchVulnerabilityList.model_validate(response.json())

    async def get_vulnerability(self, id: str) -> OsvVulnerability:
        response = await self._request("GET", f"/v1/vulns/{id}")
        return OsvVulnerability.model_validate(response.json())

    async def scan_package(
        self, package: OsvPackage, version: Optional[str] = None
    ) -> V1VulnerabilityList:
        query = V1Query(package=package, version=version)
        return await self.query(query)

    async def scan_packages(
        self, packages: List[Dict[str, Any]]
    ) -> List[V1VulnerabilityList]:
        # Simple implementation, can be optimized with batch query
        # But batch query has limits.
        # For now, let's use query_batch.

        queries = []
        for pkg in packages:
            # Construct V1Query from pkg dict
            # pkg dict expected to have name, ecosystem, version
            osv_pkg = OsvPackage(name=pkg["name"], ecosystem=pkg["ecosystem"])
            queries.append(V1Query(package=osv_pkg, version=pkg.get("version")))

        batch_results = []
        BATCH_SIZE = 1000

        for i in range(0, len(queries), BATCH_SIZE):
            chunk = queries[i : i + BATCH_SIZE]
            batch_query = V1BatchQuery(queries=chunk)
            chunk_results = (await self.query_batch(batch_query)).results
            batch_results.extend(chunk_results)

        # Collect all unique vulnerability IDs
        vuln_ids = set()
        for result in batch_results:
            if result.vulns:
                for vuln in result.vulns:
                    if vuln.id:
                        vuln_ids.add(vuln.id)

        # Fetch details for each vulnerability in parallel
        vuln_details = {}
        if vuln_ids:
            tasks = [self.get_vulnerability(vid) for vid in vuln_ids]
            details = await asyncio.gather(*tasks, return_exceptions=True)

            for vid, detail in zip(vuln_ids, details):
                if isinstance(detail, OsvVulnerability):
                    vuln_details[vid] = detail
                else:
                    logger.warning(f"Failed to fetch details for {vid}: {detail}")

        # Enrich the results
        for result in batch_results:
            if result.vulns:
                enriched_vulns = []
                for vuln in result.vulns:
                    if vuln.id in vuln_details:
                        enriched_vulns.append(vuln_details[vuln.id])
                    else:
                        enriched_vulns.append(vuln)
                result.vulns = enriched_vulns

        return batch_results
