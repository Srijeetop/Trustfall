
import requests
from datetime import datetime, timezone
from packaging.version import Version, InvalidVersion
from urllib.parse import quote


PYPI_API_URL = "https://pypi.org/pypi/{}/json"


def check_package_health(package):
    name = package["name"]
    installed_version = package["version"]

    url = PYPI_API_URL.format(quote(name, safe=""))

    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()

        data = response.json()

        latest_version = data["info"]["version"]

        try:
            update_available = (
                Version(latest_version) > Version(installed_version)
            )
        except InvalidVersion:
            update_available = None

        release_files = data.get("releases", {}).get(
            latest_version, []
        )

        release_date = None

        for release_file in release_files:
            timestamp = (
                release_file.get("upload_time_iso_8601")
                or release_file.get("upload_time")
            )

            if timestamp:
                release_date = datetime.fromisoformat(
                    timestamp.replace("Z", "+00:00")
                )
                break

        release_age_days = None

        if release_date:
            now = datetime.now(timezone.utc)
            release_age_days = (now - release_date).days

        return {
            "package": name,
            "installed_version": installed_version,
            "latest_version": latest_version,
            "update_available": update_available,
            "latest_release_date": (
                release_date.isoformat() if release_date else None
            ),
            "release_age_days": release_age_days,
            "error": None
        }

    except requests.RequestException as error:
        return {
            "package": name,
            "installed_version": installed_version,
            "latest_version": None,
            "update_available": None,
            "latest_release_date": None,
            "release_age_days": None,
            "error": str(error)
        }


def analyze_package_health(packages):
    results = []

    for package in packages:
        result = check_package_health(package)
        results.append(result)

    return results


if __name__ == "__main__":
    from dependency_discovery import discover_installed_packages

    packages = discover_installed_packages()

    print("\nAnalyzing package health...\n")

    results = analyze_package_health(packages)

    for result in results:
        print(f"\nPackage: {result['package']}")
        print(f"Installed version: {result['installed_version']}")

        if result["error"]:
            print(f"Error: {result['error']}")
            continue

        print(f"Latest version: {result['latest_version']}")
        print(f"Update available: {result['update_available']}")
        print(f"Latest release date: {result['latest_release_date']}")
        print(f"Release age (days): {result['release_age_days']}")
