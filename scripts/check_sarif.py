#!/usr/bin/env python3
"""
SARIF Quality Gate Checker

Parses CodeQL SARIF output and determines if the quality gate passes or fails.

Blocking (exit 1): Critical severity + high confidence
Warning only:     Medium severity or low confidence
"""

import json
import sys
import os

# CWE categories and their blocking behavior
BLOCKING_CWES = {
    # Critical — always block
    "CWE-120": "Buffer Overflow",
    "CWE-416": "Use-After-Free",
    "CWE-415": "Double Free",
    "CWE-78":  "Command Injection",
    "CWE-798": "Hardcoded Credentials",
    "CWE-121": "Stack Buffer Overflow",
    "CWE-122": "Heap Buffer Overflow",
    "CWE-787": "Out-of-bounds Write",
    "CWE-125": "Out-of-bounds Read",
}

WARNING_CWES = {
    # High — warning only (for training purposes)
    "CWE-134": "Format String",
    "CWE-190": "Integer Overflow",
    "CWE-338": "Insecure Random",
    "CWE-22":  "Path Traversal",
    "CWE-20":  "Unchecked Input",
    "CWE-327": "Weak Cryptography",
}

def load_sarif(filepath):
    with open(filepath, 'r') as f:
        return json.load(f)

def extract_results(sarif_data):
    """Extract results from SARIF format."""
    results = []
    for run in sarif_data.get("runs", []):
        tool_name = run.get("tool", {}).get("driver", {}).get("name", "Unknown")
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            message = result.get("message", {}).get("text", "No message")
            level = result.get("level", "warning")

            # Extract CWE from rule properties/tags
            cwes = []
            rule = None
            for r in run.get("tool", {}).get("driver", {}).get("rules", []):
                if r.get("id") == rule_id:
                    rule = r
                    break

            if rule:
                tags = rule.get("properties", {}).get("tags", [])
                for tag in tags:
                    if tag.startswith("external/cwe/CWE-"):
                        cwes.append(tag.replace("external/cwe/", ""))
                    elif tag.startswith("CWE-"):
                        cwes.append(tag)

                # Also check security-severity
                severity = rule.get("properties", {}).get("security-severity", None)

            # Extract location
            locations = []
            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                file_path = phys.get("artifactLocation", {}).get("uri", "unknown")
                region = phys.get("region", {})
                line = region.get("startLine", 0)
                locations.append(f"{file_path}:{line}")

            results.append({
                "rule_id": rule_id,
                "message": message,
                "level": level,
                "cwes": cwes,
                "locations": locations,
                "tool": tool_name,
            })

    return results

def classify_result(result):
    """Determine if a result is blocking, warning, or info."""
    rule_id = result["rule_id"]
    cwes = result["cwes"]
    level = result.get("level", "warning")

    # Check if any CWE is in the blocking list
    for cwe in cwes:
        if cwe in BLOCKING_CWES:
            if level in ("error", "warning"):
                return "blocking"

    # Check if any CWE is in the warning list
    for cwe in cwes:
        if cwe in WARNING_CWES:
            return "warning"

    # Heuristic: certain rule IDs are always blocking
    blocking_ids = [
        "cpp/potentially-dangerous-function",
        "cpp/unsafe-strcpy",
        "cpp/very-likely-overrunning-write",
        "cpp/overrunning-write",
        "cpp/use-after-free",
        "cpp/double-free",
        "cpp/command-line-injection",
        "cpp/hardcoded-credentials",
        "cpp/unbounded-write",
        "cpp/badly-bounded-write",
    ]
    if rule_id in blocking_ids:
        return "blocking"

    # Default: warning
    return "warning"

def main():
    if len(sys.argv) < 2:
        print("Usage: check_sarif.py <sarif_file>")
        sys.exit(1)

    sarif_file = sys.argv[1]
    if not os.path.exists(sarif_file):
        print(f"SARIF file not found: {sarif_file}")
        sys.exit(1)

    data = load_sarif(sarif_file)
    results = extract_results(data)

    blocking = []
    warnings = []
    infos = []

    for r in results:
        classification = classify_result(r)
        if classification == "blocking":
            blocking.append(r)
        elif classification == "warning":
            warnings.append(r)
        else:
            infos.append(r)

    # Print summary
    print(f"\nTotal findings: {len(results)}")
    print(f"  Blocking: {len(blocking)}")
    print(f"  Warnings: {len(warnings)}")
    print(f"  Info:     {len(infos)}")
    print()

    if blocking:
        print("=== BLOCKING FINDINGS ===")
        for r in blocking:
            cwe_str = ", ".join(r["cwes"]) if r["cwes"] else "N/A"
            loc_str = ", ".join(r["locations"][:3])
            print(f"  [{r['rule_id']}] {cwe_str}")
            print(f"    {r['message'][:120]}")
            print(f"    at {loc_str}")
            print()

    if warnings:
        print("=== WARNING FINDINGS (non-blocking) ===")
        for r in warnings:
            cwe_str = ", ".join(r["cwes"]) if r["cwes"] else "N/A"
            loc_str = ", ".join(r["locations"][:3])
            print(f"  [{r['rule_id']}] {cwe_str}")
            print(f"    {r['message'][:120]}")
            print(f"    at {loc_str}")
            print()

    # Determine exit code
    if blocking:
        print(f"QUALITY GATE: FAILED ({len(blocking)} blocking finding(s))")
        sys.exit(1)
    else:
        print(f"QUALITY GATE: PASSED")
        if warnings:
            print(f"  ({len(warnings)} warning(s) — review recommended)")
        sys.exit(0)


if __name__ == "__main__":
    main()
