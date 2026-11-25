
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


def analyze_requirements(
    requirements_path,
    installed_packages,
    marker_environment=None
):
    """
    Compare requirements.txt against installed packages.

    This initial version supports standard PEP 508 requirements.
    """

    requirements_path = Path(requirements_path)

    if not requirements_path.is_file():
        raise FileNotFoundError(
            f"Requirements file not found: {requirements_path}"
        )

    installed = {
        canonicalize_name(package["name"]): package
        for package in installed_packages
    }

    result = {
        "requirements_file": str(requirements_path),
        "direct_dependencies": [],
        "missing_dependencies": [],
        "version_mismatches": [],
        "installed_not_declared": [],
        "unsupported_lines": [],
        "summary": {}
    }

    declared_names = set()

    raw_content = requirements_path.read_bytes()

    if raw_content.startswith((b"\xff\xfe", b"\xfe\xff")):
        content = raw_content.decode("utf-16")
    else:
        content = raw_content.decode("utf-8-sig")

    lines = content.splitlines()

    for line_number, raw_line in enumerate(lines, start=1):

        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        # Ignore inline comments.
        line = line.split(" #", 1)[0].strip()

        try:
            requirement = Requirement(line)

        except Exception:
            result["unsupported_lines"].append({
                "line": line_number,
                "content": raw_line.strip()
            })
            continue

        # Evaluate environment markers using the target environment.
        if requirement.marker:
            applicable = requirement.marker.evaluate(
                environment=marker_environment
            )

            if not applicable:
                continue

        package_name = requirement.name
        normalized_name = canonicalize_name(package_name)

        declared_names.add(normalized_name)

        installed_package = installed.get(normalized_name)

        entry = {
            "name": package_name,
            "specifier": str(requirement.specifier),
            "installed_version": (
                installed_package["version"]
                if installed_package else None
            ),
            "status": None
        }

        if installed_package is None:
            entry["status"] = "missing"

            result["missing_dependencies"].append(entry)

        elif (
            requirement.specifier
            and not requirement.specifier.contains(
                installed_package["version"],
                prereleases=True
            )
        ):
            entry["status"] = "version_mismatch"

            result["version_mismatches"].append(entry)

        else:
            entry["status"] = "satisfied"

        result["direct_dependencies"].append(entry)

    # Find installed packages not explicitly declared.
    for normalized_name, package in installed.items():

        if normalized_name not in declared_names:
            result["installed_not_declared"].append({
                "name": package["name"],
                "version": package["version"]
            })

    result["summary"] = {
        "declared_dependencies": len(
            result["direct_dependencies"]
        ),
        "satisfied_dependencies": sum(
            1 for item in result["direct_dependencies"]
            if item["status"] == "satisfied"
        ),
        "missing_dependencies": len(
            result["missing_dependencies"]
        ),
        "version_mismatches": len(
            result["version_mismatches"]
        ),
        "installed_not_declared": len(
            result["installed_not_declared"]
        ),
        "unsupported_lines": len(
            result["unsupported_lines"]
        )
    }

    return result
