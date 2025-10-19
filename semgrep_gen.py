import json
import os
import yaml

def generate_semgrep_rules(json_file, output_dir):
    with open(json_file, 'r') as f:
        data = json.load(f)
    os.makedirs(output_dir, exist_ok=True)
    for rule in data['owasp_top20_rules']:
        rule_yml = {
            'rules': [
                {
                    'id': f"owasp.{rule['id']}",
                    'patterns': [
                        {'pattern': rule.get('sample_code', '')}
                    ],
                    'message': f"{rule['name']} - {rule['description']}",
                    'metadata': {
                        'cwe': rule['cwe'],
                        'owasp': 'Top 20',
                        'remediation': rule['fix']
                    },
                    'severity': 'WARNING',
                    'languages': ['python', 'java', 'javascript', 'html']
                }
            ]
        }
        yml_path = os.path.join(output_dir, f"{rule['id'].lower()}.yml")
        with open(yml_path, 'w') as out:
            yaml.dump(rule_yml, out, sort_keys=False)
    print(f"Generated {len(data['owasp_top20_rules'])} Semgrep rules in {output_dir}")

if __name__ == "__main__":
    generate_semgrep_rules('owasp_rules.json', 'semgrep_rules')
