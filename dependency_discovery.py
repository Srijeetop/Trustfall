
import json
import subprocess
import sys
from pathlib import Path


def discover_installed_packages(python_executable=None):
    """
    Discover installed packages.

    If python_executable is None, inspect the current Python environment.
    Otherwise, inspect the environment belonging to the supplied interpreter.
    """

    if python_executable is None:
        from importlib.metadata import distributions

        packages = []

        for dist in distributions():
            name = dist.metadata.get("Name")

            if not name:
                continue

            packages.append({
                "name": name,
                "version": dist.version,
                "requirements": dist.requires or []
            })

        packages.sort(key=lambda package: package["name"].lower())
        return packages

    executable = Path(python_executable)

    if not executable.is_file():
        raise FileNotFoundError(
            f"Python executable not found: {python_executable}"
        )

    inspection_script = r'''
import json
from importlib.metadata import distributions

packages = []

for dist in distributions():
    name = dist.metadata.get("Name")

    if not name:
        continue

    packages.append({
        "name": name,
        "version": dist.version,
        "requirements": dist.requires or []
    })

packages.sort(key=lambda package: package["name"].lower())

print(json.dumps(packages))
'''

    try:
        result = subprocess.run(
            [str(executable), "-c", inspection_script],
            capture_output=True,
            text=True,
            timeout=30,
            check=True
        )

    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            "Target environment inspection timed out."
        ) from exc

    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"Target environment inspection failed:\n{exc.stderr}"
        ) from exc

    try:
        packages = json.loads(result.stdout)

    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "Could not decode package information from target environment."
        ) from exc

    return packages


if __name__ == "__main__":

    installed_packages = discover_installed_packages()

    print(f"\nTotal packages discovered: {len(installed_packages)}\n")

    for package in installed_packages:
        print(f"{package['name']} ({package['version']})")
        print(f"  Declared dependencies: {len(package['requirements'])}")
