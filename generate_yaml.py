import json
import yaml
import os

def load_rules(json_path):
    with open(json_path, 'r') as f:
        return json.load(f)

def select_rules(rules, count):
    return rules[:count]

def generate_yaml(selected_rules, output_path='semgrep_scan.yaml'):
    yaml_structure = {'rules': selected_rules}
    with open(output_path, 'w') as f:
        yaml.dump(yaml_structure, f, sort_keys=False)

if __name__ == "__main__":
    count = int(os.getenv("RULE_COUNT", 5))  # Default to 5 if not set
    rules = load_rules('owasp_rules.json')
    selected = select_rules(rules, count)
    generate_yaml(selected)
    print(f"✅ Generated semgrep_scan.yaml with {count} rules.")
