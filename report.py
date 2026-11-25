
import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from packaging.utils import canonicalize_name

from dependency_paths import find_dependency_paths


# --------------------------------------------------
# GRAPH VISUALIZATION DATA
# --------------------------------------------------

def build_graph_visualization(graph, scan_results, health_results):

    # Index package health information.
    health_by_name = {
        canonicalize_name(result["package"]): result
        for result in health_results
    }

    # Index vulnerability findings by package.
    vulnerabilities_by_name = {}

    for finding in scan_results["findings"]:
        package_key = canonicalize_name(finding["package"])

        vulnerabilities_by_name.setdefault(
            package_key, []
        ).append(finding)

    # Identify packages whose vulnerability scan failed.
    vulnerability_errors = {
        canonicalize_name(error["package"])
        for error in scan_results["scan_errors"]
    }

    nodes = []
    node_ids = {}

    status_counts = {
        "vulnerable": 0,
        "outdated": 0,
        "healthy": 0,
        "unknown": 0
    }

    dependency_counts = {
        "direct": 0,
        "transitive": 0,
        "unexplained": 0
    }

    for node in graph["nodes"]:

        name = node["name"]
        version = node["version"]

        package_key = canonicalize_name(name)

        health = health_by_name.get(package_key)
        vulnerabilities = vulnerabilities_by_name.get(
            package_key, []
        )

        dependency_type = node.get(
            "dependency_type", "unclassified"
        )

        if dependency_type in dependency_counts:
            dependency_counts[dependency_type] += 1

        # Determine package security status.
        # Vulnerability always takes priority.
        if vulnerabilities:
            status = "vulnerable"
            color = {
                "background": "#FEE2E2",
                "border": "#DC2626"
            }

        elif (
            health is None
            or health["error"] is not None
            or package_key in vulnerability_errors
        ):
            status = "unknown"
            color = {
                "background": "#E5E7EB",
                "border": "#6B7280"
            }

        elif health["update_available"] is True:
            status = "outdated"
            color = {
                "background": "#FEF3C7",
                "border": "#D97706"
            }

        else:
            status = "healthy"
            color = {
                "background": "#D1FAE5",
                "border": "#059669"
            }

        status_counts[status] += 1

        latest_version = (
            health["latest_version"] if health else None
        )

        vulnerability_ids = [
            finding["id"] for finding in vulnerabilities
        ]

        node_id = package_key
        node_ids[package_key] = node_id

        nodes.append({
            "id": node_id,
            "label": f"{name}\n{version}",
            "name": name,
            "installed_version": version,
            "latest_version": latest_version,

            # Security classification.
            "status": status,
            "color": color,

            # Dependency classification.
            "dependency_type": dependency_type,

            "vulnerability_count": len(vulnerabilities),
            "vulnerability_ids": vulnerability_ids,

            "release_age_days": (
                health["release_age_days"] if health else None
            ),

            "title": (
                f"Package: {name}\n"
                f"Installed: {version}\n"
                f"Latest: {latest_version or 'Unknown'}\n"
                f"Security status: {status}\n"
                f"Dependency type: {dependency_type}\n"
                f"Vulnerabilities: {len(vulnerabilities)}"
            )
        })

    # Convert dependency relationships into graph edges.
    edges = []

    for edge in graph["edges"]:

        parent = canonicalize_name(edge["parent"])
        child = canonicalize_name(edge["child"])

        if parent not in node_ids or child not in node_ids:
            continue

        edges.append({
            "from": node_ids[parent],
            "to": node_ids[child],
            "arrows": "to",
            "constraint": edge["constraint"],
            "constraint_satisfied": edge["constraint_satisfied"]
        })

    return {
        "nodes": nodes,
        "edges": edges,
        "status_summary": status_counts,
        "dependency_summary": dependency_counts
    }


# --------------------------------------------------
# REPORT GENERATION
# --------------------------------------------------

def generate_report(
    environment,
    packages,
    graph,
    scan_results,
    health_results
):

    findings = []

    for finding in scan_results["findings"]:

        item = finding.copy()

        paths = find_dependency_paths(
            graph,
            item["package"]
        )

        item["dependency_paths"] = paths

        findings.append(item)

    updates_available = sum(
        1 for result in health_results
        if result["update_available"] is True
    )

    health_errors = sum(
        1 for result in health_results
        if result["error"] is not None
    )

    graph_visualization = build_graph_visualization(
        graph,
        scan_results,
        health_results
    )

    dependency_summary = graph.get(
        "dependency_summary",
        {
            "direct": 0,
            "transitive": 0,
            "unexplained": 0
        }
    )

    report = {
        "tool": "TrustFall",

        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),

        "environment": environment,

        "summary": {
            "total_packages": len(packages),
            "total_nodes": len(graph["nodes"]),
            "total_edges": len(graph["edges"]),

            "missing_dependencies": len(
                graph["missing_dependencies"]
            ),

            "advisory_records": scan_results["raw_finding_count"],
            "unique_findings": len(findings),
            "scan_errors": len(scan_results["scan_errors"]),

            "updates_available": updates_available,
            "package_health_errors": health_errors,

            "direct_dependencies": dependency_summary["direct"],
            "transitive_dependencies": dependency_summary["transitive"],
            "unexplained_packages": dependency_summary["unexplained"]
        },

        "dependency_summary": dependency_summary,

        "packages": packages,

        "dependency_graph": graph,

        "dependency_visualization": graph_visualization,

        "vulnerability_scan": {
            "findings": findings,
            "scan_errors": scan_results["scan_errors"]
        },

        "package_health": {
            "results": health_results,
            "updates_available": updates_available,
            "analysis_errors": health_errors
        }
    }

    return report


# --------------------------------------------------
# JSON REPORT
# --------------------------------------------------

def save_report(report, filename="trustfall_report.json"):

    output_path = Path(filename)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False
        )

    return output_path.resolve()


# --------------------------------------------------
# HTML REPORT
# --------------------------------------------------

def save_html_report(
    report,
    filename="trustfall_report.html"
):

    template_directory = Path(__file__).parent / "templates"

    template_environment = Environment(
        loader=FileSystemLoader(str(template_directory)),
        autoescape=select_autoescape(["html", "xml"])
    )

    template = template_environment.get_template(
        "report.html"
    )

    html_content = template.render(report=report)

    output_path = Path(filename)

    with output_path.open("w", encoding="utf-8") as file:
        file.write(html_content)

    return output_path.resolve()


if __name__ == "__main__":
    print("TrustFall report module.")
    print("Run main.py to generate reports.")
