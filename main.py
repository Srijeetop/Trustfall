
import argparse
import re
from pathlib import Path

from environment import inspect_environment
from dependency_discovery import discover_installed_packages
from dependency_graph import build_dependency_graph
from dependency_paths import find_dependency_paths
from vulnerability_scanner import scan_installed_packages
from report import generate_report, save_report, save_html_report
from package_health import analyze_package_health
from manifest_analyzer import analyze_requirements


def find_project_interpreter(project_path):
    """Find a conventional virtual environment interpreter."""

    candidates = [
        project_path / "venv" / "Scripts" / "python.exe",
        project_path / ".venv" / "Scripts" / "python.exe",
        project_path / "venv" / "bin" / "python",
        project_path / ".venv" / "bin" / "python",
    ]

    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)

    return None


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="TrustFall - Software Supply Chain Security Analyzer"
    )

    parser.add_argument(
        "--project",
        help="Path to the external project you want to scan."
    )

    parser.add_argument(
        "--python",
        help="Explicit path to the target project's Python interpreter."
    )

    args = parser.parse_args()

    if args.python and not args.project:
        parser.error("--python can only be used together with --project.")

    return args


def main():
    args = parse_arguments()

    print("=" * 60)
    print("       TRUSTFALL - SUPPLY CHAIN SECURITY ANALYZER")
    print("=" * 60)

    # --------------------------------------------------
    # 1. Determine scan target
    # --------------------------------------------------

    target_python = None
    project_path = None

    if args.project:
        project_path = Path(args.project).resolve()

        if not project_path.is_dir():
            raise FileNotFoundError(
                f"Project directory does not exist: {project_path}"
            )

        target_python = (
            args.python or find_project_interpreter(project_path)
        )

        if not target_python:
            raise RuntimeError(
                "No virtual environment was found in the project.\n"
                "Use --python to specify its Python interpreter."
            )

        target_python = str(Path(target_python).resolve())

        if not Path(target_python).is_file():
            raise FileNotFoundError(
                f"Python interpreter does not exist: {target_python}"
            )

        print(f"\nScan target: {project_path}")
        print(f"Target interpreter: {target_python}")

    else:
        print("\nScan target: TrustFall's own environment")

    # --------------------------------------------------
    # 2. Inspect Python environment
    # --------------------------------------------------

    print("\n[1] Inspecting Python environment...\n")

    environment = inspect_environment(target_python)

    for key, value in environment.items():
        if key == "marker_environment":
            continue

        print(f"{key.replace('_', ' ').title():25}: {value}")

    if project_path:
        environment["scan_target"] = "external_project"
        environment["project_path"] = str(project_path)
    else:
        environment["scan_target"] = "trustfall"

    # --------------------------------------------------
    # 3. Discover installed packages
    # --------------------------------------------------

    print("\n[2] Discovering installed packages...\n")

    packages = discover_installed_packages(target_python)

    print(f"Total packages discovered: {len(packages)}")

    # --------------------------------------------------
    # 3A. Analyze project dependency manifest
    # --------------------------------------------------

    manifest_analysis = None

    if project_path:
        requirements_path = project_path / "requirements.txt"

        if requirements_path.is_file():
            print("\n[2A] Analyzing requirements.txt...\n")

            manifest_analysis = analyze_requirements(
                requirements_path,
                packages,
                environment["marker_environment"]
            )

            summary = manifest_analysis["summary"]

            print(
                f"Declared dependencies: "
                f"{summary['declared_dependencies']}"
            )

            print(
                f"Satisfied dependencies: "
                f"{summary['satisfied_dependencies']}"
            )

            print(
                f"Missing dependencies: "
                f"{summary['missing_dependencies']}"
            )

            print(
                f"Version mismatches: "
                f"{summary['version_mismatches']}"
            )

            print(
                f"Installed but not declared: "
                f"{summary['installed_not_declared']}"
            )

            print(
                f"Unsupported lines: "
                f"{summary['unsupported_lines']}"
            )

            if manifest_analysis["missing_dependencies"]:
                print("\nMissing packages:")

                for item in manifest_analysis["missing_dependencies"]:
                    print(f"  - {item['name']}")

            if manifest_analysis["version_mismatches"]:
                print("\nVersion mismatches:")

                for item in manifest_analysis["version_mismatches"]:
                    print(
                        f"  - {item['name']}: "
                        f"required {item['specifier']}, "
                        f"installed {item['installed_version']}"
                    )

            if manifest_analysis["unsupported_lines"]:
                print("\nUnsupported requirements lines:")

                for item in manifest_analysis["unsupported_lines"]:
                    print(
                        f"  Line {item['line']}: {item['content']}"
                    )

        else:
            print(
                "\nNo requirements.txt found. "
                "Skipping manifest analysis."
            )

    # --------------------------------------------------
    # 4. Build dependency graph and classify packages
    # --------------------------------------------------

    print("\n[3] Building dependency graph...\n")

    direct_dependencies = []

    if manifest_analysis:
        direct_dependencies = [
            item["name"]
            for item in manifest_analysis["direct_dependencies"]
        ]

    graph = build_dependency_graph(
        packages,
        environment["marker_environment"],
        direct_dependencies
    )

    print(f"Total nodes: {len(graph['nodes'])}")
    print(f"Total edges: {len(graph['edges'])}")
    print(
        f"Missing dependencies: "
        f"{len(graph['missing_dependencies'])}"
    )

    if "dependency_summary" in graph:
        summary = graph["dependency_summary"]

        print("\nDependency classification:")
        print(f"Direct dependencies: {summary['direct']}")
        print(f"Transitive dependencies: {summary['transitive']}")
        print(f"Unexplained packages: {summary['unexplained']}")

    # --------------------------------------------------
    # 5. Vulnerability scanning
    # --------------------------------------------------

    print("\n[4] Scanning packages against OSV...\n")

    scan_results = scan_installed_packages(packages)
    findings = scan_results["findings"]

    print(
        f"Advisory records returned: "
        f"{scan_results['raw_finding_count']}"
    )

    print(f"Unique vulnerabilities: {len(findings)}")

    print(
        f"Packages with scan errors: "
        f"{len(scan_results['scan_errors'])}"
    )

    # --------------------------------------------------
    # 6. Package health analysis
    # --------------------------------------------------

    print("\n[5] Analyzing package health...\n")

    health_results = analyze_package_health(packages)

    updates_available = sum(
        1 for result in health_results
        if result["update_available"] is True
    )

    health_errors = sum(
        1 for result in health_results
        if result["error"] is not None
    )

    print(f"Packages analyzed: {len(health_results)}")
    print(f"Updates available: {updates_available}")
    print(f"Analysis errors: {health_errors}")

    for result in health_results:
        if result["update_available"] is True:
            print(
                f"  Update available: {result['package']} "
                f"({result['installed_version']} -> "
                f"{result['latest_version']})"
            )

    # --------------------------------------------------
    # 7. Display security findings
    # --------------------------------------------------

    print("\n[6] Security findings and dependency paths")
    print("-" * 60)

    if not findings:
        print("No known vulnerabilities were reported.")

    for index, finding in enumerate(findings, start=1):
        package_name = finding["package"]

        print(f"\nFinding {index}")
        print(f"Package: {package_name}")
        print(f"Installed version: {finding['version']}")
        print(f"Advisory ID: {finding['id']}")
        print(f"Summary: {finding['summary']}")

        if finding["aliases"]:
            print(f"Related IDs: {', '.join(finding['aliases'])}")

        print("\nSeverity:")

        if finding["severity"]:
            for severity in finding["severity"]:
                print(
                    f"  {severity.get('type', 'Unknown')}: "
                    f"{severity.get('score', 'Not provided')}"
                )
        else:
            print("  Not provided")

        print("\nCandidate fixed versions:")

        if finding["fixed_versions"]:
            for version in finding["fixed_versions"]:
                print(f"  - {version}")
        else:
            print("  No fixed version provided")

        paths = find_dependency_paths(graph, package_name)

        print("\nDependency path:")

        if paths:
            for path in paths:
                print("  " + " -> ".join(path))
        else:
            print("  No dependency path could be reconstructed.")

    # --------------------------------------------------
    # 8. Generate reports
    # --------------------------------------------------

    print("\n[7] Generating security reports...\n")

    report_data = generate_report(
        environment,
        packages,
        graph,
        scan_results,
        health_results
    )

    # Attach manifest analysis to report.
    report_data["manifest_analysis"] = manifest_analysis

    if project_path:
        safe_name = re.sub(
            r"[^A-Za-z0-9_-]+",
            "_",
            project_path.name
        )

        json_filename = f"{safe_name}_trustfall_report.json"
        html_filename = f"{safe_name}_trustfall_report.html"

    else:
        json_filename = "trustfall_report.json"
        html_filename = "trustfall_report.html"

    json_path = save_report(report_data, json_filename)
    html_path = save_html_report(report_data, html_filename)

    print("JSON report generated successfully!")
    print(f"JSON location: {json_path}")

    print("\nHTML report generated successfully!")
    print(f"HTML location: {html_path}")

    # --------------------------------------------------
    # 9. Display scan errors
    # --------------------------------------------------

    if scan_results["scan_errors"]:
        print("\nSCAN ERRORS")
        print("-" * 60)

        for error in scan_results["scan_errors"]:
            print(f"{error['package']}: {error['error']}")

    print("\n" + "=" * 60)
    print("TrustFall scan completed.")
    print("=" * 60)


if __name__ == "__main__":
    main()
