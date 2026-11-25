
import json
import subprocess
import sys
from pathlib import Path


def inspect_environment(python_executable=None):

    if python_executable is None:
        from packaging.markers import default_environment
        import platform

        return {
            "python_version": platform.python_version(),
            "python_executable": sys.executable,
            "operating_system": platform.system(),
            "is_virtual_environment": sys.prefix != sys.base_prefix,
            "environment_path": sys.prefix,
            "marker_environment": default_environment()
        }

    executable = Path(python_executable)

    if not executable.is_file():
        raise FileNotFoundError(
            f"Python executable not found: {python_executable}"
        )

    inspection_script = r'''
import json
import platform
import sys
from packaging.markers import default_environment

environment = {
    "python_version": platform.python_version(),
    "python_executable": sys.executable,
    "operating_system": platform.system(),
    "is_virtual_environment": sys.prefix != sys.base_prefix,
    "environment_path": sys.prefix,
    "marker_environment": default_environment()
}

print(json.dumps(environment))
'''

    try:
        result = subprocess.run(
            [str(executable), "-c", inspection_script],
            capture_output=True,
            text=True,
            timeout=30,
            check=True
        )

        return json.loads(result.stdout)

    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            "Target environment inspection timed out."
        ) from exc

    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"Target environment inspection failed:\n{exc.stderr}"
        ) from exc

    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "Could not decode target environment information."
        ) from exc


if __name__ == "__main__":

    details = inspect_environment()

    for key, value in details.items():
        print(f"{key}: {value}")
