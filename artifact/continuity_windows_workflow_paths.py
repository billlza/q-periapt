"""Path coverage for the restricted globs used by Windows qualification."""
import re


def _paths(text):
    header = text.split("\npermissions:\n", 1)[0]
    match = re.search(r"(?m)^    paths:\n((?:      - [^\n]+\n)+)", header)
    if match is None or "    paths-ignore:" in header:
        raise ValueError("expected explicit workflow path filters")
    return [line.removeprefix("      - ") for line in match[1].splitlines()]


def path_matches(pattern, path):
    # The maintained workflow uses only literal paths, * and **. Unlike
    # fnmatch, GitHub's single * must not cross a directory separator.
    if any(character in pattern for character in "!+?[]{}"):
        raise ValueError("unsupported workflow path pattern")
    expression, index = "", 0
    while index < len(pattern):
        if pattern[index:index + 3] == "**/":
            expression += "(?:.*/)?"
            index += 3
        elif pattern[index:index + 2] == "**":
            expression += ".*"
            index += 2
        elif pattern[index] == "*":
            expression += "[^/]*"
            index += 1
        else:
            expression += re.escape(pattern[index])
            index += 1
    return re.fullmatch(expression, path) is not None


def triggered(patterns, path):
    return any(path_matches(pattern, path) for pattern in patterns)


def event_paths(text):
    header = text.split("\npermissions:\n", 1)[0]
    push, pr = header.split("\n  pull_request:\n", 1)
    if "\n  push:\n" not in push:
        raise ValueError("expected push trigger")
    return {"push": _paths(push + "\n"), "pull_request": _paths(pr + "\n")}
