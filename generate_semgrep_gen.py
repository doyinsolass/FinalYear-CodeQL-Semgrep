import json
import sys
import yaml

json_file = sys.argv[1]
output_yaml = sys.argv[2]

with open(json_file) as f:
    data = json.load(f)

rules = []
for r in data["owasp_top20_rules"]:
    rules.append({
        "id": r["id"],
        "patterns": [{"pattern-regex": r["pattern"]}],
        "message": r["description"],
        "languages": r["languages"],
        "severity": r.get("severity", "ERROR"),
        "metadata": {"cwe": r.get("cwe")}
    })

with open(output_yaml, "w") as f:
    yaml.dump({"rules": rules}, f, sort_keys=False)
