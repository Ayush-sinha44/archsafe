"""AUR package information fetcher."""

from __future__ import annotations

from datetime import datetime, timezone

import requests

from archsafe.models import AURPackageInfo


AUR_RPC_URL = "https://aur.archlinux.org/rpc/v5/info"
AUR_PKGBUILD_URL = "https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD"


def fetch_package_info(name: str) -> AURPackageInfo:
    """Fetch package metadata from the AUR RPC API.

    Args:
        name: The AUR package name.

    Returns:
        AURPackageInfo populated with metadata.

    Raises:
        ValueError: If the package is not found.
        requests.RequestException: On network errors.
    """
    response = requests.get(AUR_RPC_URL, params={"arg[]": name}, timeout=15)
    response.raise_for_status()
    data = response.json()

    if data.get("resultcount", 0) == 0:
        raise ValueError(f"Package '{name}' not found in the AUR.")

    pkg = data["results"][0]

    return AURPackageInfo(
        name=pkg["Name"],
        version=pkg.get("Version", "unknown"),
        description=pkg.get("Description", ""),
        num_votes=pkg.get("NumVotes", 0),
        popularity=pkg.get("Popularity", 0.0),
        maintainer=pkg.get("Maintainer"),
        first_submitted=datetime.fromtimestamp(
            pkg.get("FirstSubmitted", 0), tz=timezone.utc
        ),
        last_modified=datetime.fromtimestamp(
            pkg.get("LastModified", 0), tz=timezone.utc
        ),
        out_of_date=(
            datetime.fromtimestamp(pkg["OutOfDate"], tz=timezone.utc)
            if pkg.get("OutOfDate")
            else None
        ),
        url=pkg.get("URL"),
        depends=pkg.get("Depends", []) or [],
        make_depends=pkg.get("MakeDepends", []) or [],
    )


def fetch_pkgbuild(name: str) -> str:
    """Download the PKGBUILD for an AUR package.

    Args:
        name: The AUR package name.

    Returns:
        Raw PKGBUILD content as a string.

    Raises:
        ValueError: If the PKGBUILD cannot be found.
        requests.RequestException: On network errors.
    """
    response = requests.get(AUR_PKGBUILD_URL, params={"h": name}, timeout=15)

    if response.status_code == 404:
        raise ValueError(f"PKGBUILD not found for package '{name}'.")

    response.raise_for_status()
    return response.text
