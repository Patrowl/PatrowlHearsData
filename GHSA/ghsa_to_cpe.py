#!/usr/bin/env python3
"""Fetch a GitHub Security Advisory JSON file and suggest CPE 2.3 vectors.

The script intentionally treats CPEs as suggestions. GHSA package names are
ecosystem-native identifiers, while CPE vendor/product names are curated by NVD.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote_plus
from urllib.request import Request, urlopen


DEFAULT_ADVISORY_URL = (
    "https://raw.githubusercontent.com/github/advisory-database/refs/heads/main/"
    "advisories/github-reviewed/2026/06/GHSA-3q2p-72cj-682c/"
    "GHSA-3q2p-72cj-682c.json"
)

NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

ssl_context = ssl._create_unverified_context()


@dataclass(frozen=True)
class PackageCpeGuess:
    ecosystem: str
    package: str
    vendor: str
    product: str
    confidence: str
    reason: str

    @property
    def wildcard_criteria(self) -> str:
        return format_cpe(self.vendor, self.product, "*")

    def exact_criteria(self, version: str) -> str:
        return format_cpe(self.vendor, self.product, version)


def fetch_json(url: str) -> dict[str, Any]:
    request = Request(url, headers={"User-Agent": "ghsa-to-cpe/1.0"})
    try:
        with urlopen(request, timeout=30, context=ssl_context) as response:
            return json.load(response)
    except HTTPError as exc:
        raise SystemExit(f"HTTP {exc.code} while fetching {url}") from exc
    except URLError as exc:
        raise SystemExit(f"Unable to fetch {url}: {exc.reason}") from exc


def cpe_component(value: str) -> str:
    """Return a conservative CPE 2.3 formatted-string component."""
    value = value.strip().lower()
    value = value.removeprefix("@")
    value = re.sub(r"[\s/]+", "_", value)
    value = re.sub(r"[^a-z0-9._-]", "_", value)
    value = re.sub(r"_+", "_", value).strip("_")
    return value or "*"


def format_cpe(vendor: str, product: str, version: str = "*") -> str:
    return (
        f"cpe:2.3:a:{cpe_component(vendor)}:{cpe_component(product)}:"
        f"{cpe_component(version)}:*:*:*:*:*:*:*"
    )


def module_major_start_version(ecosystem: str, package: str) -> str | None:
    if ecosystem.lower() != "go":
        return None

    match = re.search(r"/v([2-9][0-9]*)$", package)
    if not match:
        return None

    return f"{match.group(1)}.0.0"


def guess_cpe_for_package(ecosystem: str, package: str) -> PackageCpeGuess:
    """Infer likely CPE vendor/product fields from an ecosystem package name."""
    ecosystem_lower = ecosystem.lower()

    if ecosystem_lower == "go" and package.startswith("github.com/"):
        parts = package.split("/")
        if len(parts) >= 3:
            owner, repo = parts[1], parts[2]
            return PackageCpeGuess(
                ecosystem=ecosystem,
                package=package,
                vendor=owner,
                product=repo,
                confidence="medium",
                reason="Go module is hosted at github.com/<owner>/<repo>; CPE usually tracks the upstream project.",
            )

    if ecosystem_lower == "npm" and package.startswith("@"):
        scope, _, name = package[1:].partition("/")
        if scope and name:
            return PackageCpeGuess(
                ecosystem=ecosystem,
                package=package,
                vendor=scope,
                product=name,
                confidence="low",
                reason="Scoped npm package mapped from @scope/name.",
            )

    if "/" in package:
        vendor, _, product = package.partition("/")
        return PackageCpeGuess(
            ecosystem=ecosystem,
            package=package,
            vendor=vendor,
            product=product,
            confidence="low",
            reason="Package name split on the first slash.",
        )

    return PackageCpeGuess(
        ecosystem=ecosystem,
        package=package,
        vendor=package,
        product=package,
        confidence="low",
        reason="No ecosystem-specific mapping available; package name reused as vendor and product.",
    )


def purl_for_package(ecosystem: str, package: str) -> str | None:
    purl_type_by_ecosystem = {
        "go": "golang",
        "npm": "npm",
        "pip": "pypi",
        "maven": "maven",
        "rubygems": "gem",
        "composer": "composer",
        "nuget": "nuget",
        "cargo": "cargo",
    }
    purl_type = purl_type_by_ecosystem.get(ecosystem.lower())
    if not purl_type:
        return None
    return f"pkg:{purl_type}/{package}"


def affected_range_to_cpe_match(
    cpe_guess: PackageCpeGuess, range_entry: dict[str, Any]
) -> dict[str, Any]:
    cpe_match: dict[str, Any] = {
        "vulnerable": True,
        "criteria": cpe_guess.wildcard_criteria,
        "cpe23Uri": cpe_guess.wildcard_criteria,
        "matchCriteriaStatus": "SUGGESTED",
    }

    for event in range_entry.get("events", []):
        if "introduced" in event:
            if event["introduced"] != "0":
                cpe_match["versionStartIncluding"] = event["introduced"]
            else:
                major_start = module_major_start_version(
                    cpe_guess.ecosystem, cpe_guess.package
                )
                if major_start:
                    cpe_match["versionStartIncluding"] = major_start
        if "fixed" in event:
            cpe_match["versionEndExcluding"] = event["fixed"]
        if "last_affected" in event:
            cpe_match["versionEndIncluding"] = event["last_affected"]
        if "limit" in event:
            cpe_match["versionEndExcluding"] = event["limit"]

    return cpe_match


def last_known_affected_version(affected: dict[str, Any]) -> str | None:
    database_specific = affected.get("database_specific", {})
    version_range = database_specific.get("last_known_affected_version_range")
    if not isinstance(version_range, str):
        return None
    match = re.search(r"([0-9]+(?:\.[0-9A-Za-z_-]+)+)$", version_range.strip())
    return match.group(1) if match else None


def exact_versions_from_ranges(affected: dict[str, Any]) -> list[str]:
    versions: list[str] = []
    last_known = last_known_affected_version(affected)
    if last_known:
        versions.append(last_known)

    for range_entry in affected.get("ranges", []):
        for event in range_entry.get("events", []):
            if "last_affected" in event:
                versions.append(event["last_affected"])

    return sorted(set(versions), key=versions.index)


def advisory_to_cpe_suggestions(advisory: dict[str, Any]) -> dict[str, Any]:
    results: list[dict[str, Any]] = []

    for affected in advisory.get("affected", []):
        package_info = affected.get("package", {})
        ecosystem = package_info.get("ecosystem", "")
        package = package_info.get("name", "")
        cpe_guess = guess_cpe_for_package(ecosystem, package)

        ranges = affected.get("ranges", [])
        cpe_matches = [
            affected_range_to_cpe_match(cpe_guess, range_entry)
            for range_entry in ranges
        ]
        exact_versions = exact_versions_from_ranges(affected)

        results.append(
            {
                "ecosystem": ecosystem,
                "package": package,
                "purl": purl_for_package(ecosystem, package),
                "affected_ranges": ranges,
                "cpe": {
                    "vendor": cpe_guess.vendor,
                    "product": cpe_guess.product,
                    "confidence": cpe_guess.confidence,
                    "reason": cpe_guess.reason,
                    "criteria": cpe_guess.wildcard_criteria,
                    "representative_exact_criteria": [
                        cpe_guess.exact_criteria(version)
                        for version in exact_versions
                    ],
                    "cpeMatch": cpe_matches,
                },
            }
        )

    return {
        "id": advisory.get("id"),
        "aliases": advisory.get("aliases", []),
        "summary": advisory.get("summary"),
        "modified": advisory.get("modified"),
        "affected": results,
    }


def fetch_nvd_cpe_names(keyword: str) -> list[str]:
    url = f"{NVD_CPE_API}?keywordSearch={quote_plus(keyword)}"
    data = fetch_json(url)
    names: list[str] = []
    for product in data.get("products", []):
        cpe = product.get("cpe", {})
        cpe_name = cpe.get("cpeName")
        if cpe_name:
            names.append(cpe_name)
    return names


def enrich_with_nvd_matches(suggestions: dict[str, Any]) -> None:
    cpe_name_cache: dict[str, list[str]] = {}

    for affected in suggestions["affected"]:
        cpe = affected["cpe"]
        keyword = f"{cpe['vendor']} {cpe['product']}"
        try:
            if keyword not in cpe_name_cache:
                cpe_name_cache[keyword] = fetch_nvd_cpe_names(keyword)
            matches = cpe_name_cache[keyword]
        except SystemExit as exc:
            affected["nvd_lookup_error"] = str(exc)
            continue

        prefix = f"cpe:2.3:a:{cpe_component(cpe['vendor'])}:{cpe_component(cpe['product'])}:"
        affected["nvd_known_product_cpes"] = [
            name for name in matches if name.startswith(prefix)
        ][:25]
        if affected["nvd_known_product_cpes"]:
            cpe["confidence"] = "medium"
            cpe["reason"] += " Matching vendor/product CPE names were found in NVD."


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch a GHSA advisory and suggest CPE vectors for affected packages."
    )
    parser.add_argument(
        "url",
        nargs="?",
        default=DEFAULT_ADVISORY_URL,
        help="Raw GHSA advisory JSON URL.",
    )
    parser.add_argument(
        "--check-nvd",
        action="store_true",
        help="Query NVD's CPE API and include matching known CPE names.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    advisory = fetch_json(args.url)
    suggestions = advisory_to_cpe_suggestions(advisory)

    if args.check_nvd:
        enrich_with_nvd_matches(suggestions)

    json.dump(suggestions, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
