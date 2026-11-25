
from collections import deque
from packaging.utils import canonicalize_name


def find_dependency_paths(graph, target, max_paths=10):
    target = canonicalize_name(target)

    nodes = {
        canonicalize_name(node["name"]): node["name"]
        for node in graph["nodes"]
    }

    if target not in nodes:
        return []

    # Identify packages that are not dependencies of other packages.
    children = {
        canonicalize_name(edge["child"])
        for edge in graph["edges"]
    }

    roots = [
        name for name in nodes
        if name not in children
    ]

    paths = []

    # Search from each root towards the target.
    for root in roots:
        queue = deque([[root]])

        while queue and len(paths) < max_paths:
            path = queue.popleft()
            current = path[-1]

            if current == target:
                paths.append([
                    nodes[name] for name in path
                ])
                continue

            for edge in graph["edges"]:
                parent = canonicalize_name(edge["parent"])
                child = canonicalize_name(edge["child"])

                if parent == current and child not in path:
                    queue.append(path + [child])

    return paths


if __name__ == "__main__":
    from dependency_discovery import discover_installed_packages
    from dependency_graph import build_dependency_graph

    packages = discover_installed_packages()
    graph = build_dependency_graph(packages)

    target = input("Enter package name to trace: ").strip()
    paths = find_dependency_paths(graph, target)

    if not paths:
        print(f"No dependency path found for {target}.")
    else:
        print(f"\nDependency paths to {target}:\n")

        for index, path in enumerate(paths, start=1):
            print(f"Path {index}: {' -> '.join(path)}")
