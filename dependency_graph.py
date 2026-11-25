
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


def build_dependency_graph(
    packages,
    marker_environment=None,
    direct_dependencies=None
):
    installed = {
        canonicalize_name(package["name"]): package
        for package in packages
    }

    # Normalize direct dependency names.
    direct_names = {
        canonicalize_name(name)
        for name in (direct_dependencies or [])
    }

    graph = {
        "nodes": [],
        "edges": [],
        "missing_dependencies": []
    }

    # Add all installed packages as graph nodes.
    for normalized_name, package in installed.items():

        if normalized_name in direct_names:
            dependency_type = "direct"
        else:
            dependency_type = "unexplained"

        graph["nodes"].append({
            "name": package["name"],
            "version": package["version"],
            "dependency_type": dependency_type
        })

    # Establish parent-child relationships.
    for package in installed.values():

        for raw_requirement in package["requirements"]:

            try:
                requirement = Requirement(raw_requirement)

                if requirement.marker:
                    applicable = requirement.marker.evaluate(
                        environment=marker_environment
                    ) if marker_environment is not None else (
                        requirement.marker.evaluate()
                    )

                    if not applicable:
                        continue

                child = canonicalize_name(requirement.name)

                if child not in installed:

                    graph["missing_dependencies"].append({
                        "parent": package["name"],
                        "dependency": requirement.name,
                        "constraint": str(requirement.specifier)
                    })

                    continue

                child_package = installed[child]

                constraint_satisfied = (
                    not requirement.specifier
                    or requirement.specifier.contains(
                        child_package["version"],
                        prereleases=True
                    )
                )

                graph["edges"].append({
                    "parent": package["name"],
                    "child": child_package["name"],
                    "constraint": str(requirement.specifier),
                    "constraint_satisfied": constraint_satisfied
                })

            except Exception as error:

                print(
                    f"Could not parse requirement "
                    f"'{raw_requirement}' from "
                    f"{package['name']}: {error}"
                )

    # Build adjacency list using parent -> child relationships.
    adjacency = {}

    for edge in graph["edges"]:
        parent = canonicalize_name(edge["parent"])
        child = canonicalize_name(edge["child"])

        adjacency.setdefault(parent, []).append(child)

    # Find every package reachable from a direct dependency.
    reachable = set()
    pending = list(direct_names)

    while pending:

        current = pending.pop()

        if current in reachable:
            continue

        reachable.add(current)

        for child in adjacency.get(current, []):
            if child not in reachable:
                pending.append(child)

    # Assign final dependency classifications.
    for node in graph["nodes"]:

        normalized_name = canonicalize_name(node["name"])

        if normalized_name in direct_names:
            node["dependency_type"] = "direct"

        elif normalized_name in reachable:
            node["dependency_type"] = "transitive"

        else:
            node["dependency_type"] = "unexplained"

    # Add classification summary.
    graph["dependency_summary"] = {
        "direct": sum(
            1 for node in graph["nodes"]
            if node["dependency_type"] == "direct"
        ),
        "transitive": sum(
            1 for node in graph["nodes"]
            if node["dependency_type"] == "transitive"
        ),
        "unexplained": sum(
            1 for node in graph["nodes"]
            if node["dependency_type"] == "unexplained"
        )
    }

    return graph


if __name__ == "__main__":

    from dependency_discovery import discover_installed_packages

    packages = discover_installed_packages()

    graph = build_dependency_graph(packages)

    print("\nDEPENDENCY GRAPH")
    print("-" * 45)

    print(f"Total nodes: {len(graph['nodes'])}")
    print(f"Total edges: {len(graph['edges'])}")
    print(f"Missing dependencies: {len(graph['missing_dependencies'])}")

    for edge in graph["edges"]:
        print(f"{edge['parent']} ---> {edge['child']}")

    print("\nDEPENDENCY CLASSIFICATION")
    print("-" * 45)

    for node in graph["nodes"]:
        print(
            f"{node['name']} ({node['version']}) "
            f"--> {node['dependency_type']}"
        )

    print("\nSummary:", graph["dependency_summary"])
