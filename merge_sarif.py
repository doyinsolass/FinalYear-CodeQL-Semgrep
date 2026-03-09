import json
import os
import sys


def load_sarif(path: str):
  if not os.path.isfile(path):
    print(f"[merge_sarif] File not found: {path}", file=sys.stderr)
    return None
  try:
    with open(path, "r", encoding="utf-8") as f:
      data = json.load(f)
  except Exception as e:
    print(f"[merge_sarif] Failed to parse {path} as JSON: {e}", file=sys.stderr)
    return None
  if not isinstance(data, dict) or "runs" not in data or not isinstance(data["runs"], list):
    print(f"[merge_sarif] {path} is not valid SARIF (missing 'runs' array).", file=sys.stderr)
    return None
  return data


def main():
  semgrep_path = "semgrep_results.sarif"
  codeql_path = "codeql-results.sarif"
  output_path = "merged.sarif"

  semgrep_sarif = load_sarif(semgrep_path)
  codeql_sarif = load_sarif(codeql_path)

  runs = []

  if semgrep_sarif is not None:
    print(f"[merge_sarif] Adding runs from {semgrep_path}")
    runs.extend(semgrep_sarif.get("runs", []))
  else:
    print(f"[merge_sarif] No valid SARIF from {semgrep_path}")

  if codeql_sarif is not None:
    print(f"[merge_sarif] Adding runs from {codeql_path}")
    runs.extend(codeql_sarif.get("runs", []))
  else:
    print(f"[merge_sarif] No valid SARIF from {codeql_path}")

  if not runs:
    print("[merge_sarif] No runs found in any SARIF file. Creating empty SARIF.", file=sys.stderr)

  merged_sarif = {
    "version": "2.1.0",
    "runs": runs,
  }

  schema = None
  if semgrep_sarif is not None:
    schema = semgrep_sarif.get("$schema")
  if schema is None and codeql_sarif is not None:
    schema = codeql_sarif.get("$schema")
  if schema is not None:
    merged_sarif["$schema"] = schema

  with open(output_path, "w", encoding="utf-8") as f:
    json.dump(merged_sarif, f, indent=2)

  print(f"[merge_sarif] Wrote merged SARIF to {output_path}")


if __name__ == "__main__":
  main()
