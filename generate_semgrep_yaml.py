import json
import sys
import yaml

if len(sys.argv) != 3:
    print("Usage: python generate_semgrep_yaml.py <owasp_rules.json> <output.yml>")
    sys.exit(1)

input_json = sys.argv[1]
output_yml = sys.argv[2]

with open(input_json) as f:
    data = json.load(f)

rules = []
for rule in data["owasp_top20_rules"]:
    patterns_list = []
    for pattern in rule.get("patterns", []):
        patterns_list.append({"pattern-regex": pattern})

    rules.append({
        "id": rule["id"],
        "patterns": patterns_list,
        "message": f"{rule['name']} detected. {rule['description']} Fix: {rule['fix']}",
        "languages": ["python", "java", "javascript", "html"],
        "severity": "ERROR",
        "metadata": {"cwe": rule["cwe"]}
    })

semgrep_yaml = {"rules": rules}

with open(output_yml, "w") as f:
    yaml.dump(semgrep_yaml, f, sort_keys=False)

print(f"Generated {len(rules)} Semgrep rules in {output_yml}")
