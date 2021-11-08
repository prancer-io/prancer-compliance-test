import json
import os

cases = []
testSet = {}
exclude_list = []
for file in os.listdir("./"):
    if file.endswith(".rego") and file not in exclude_list:
        print(file)
        file_name = file

        with open(file_name, "r") as rego_file:
            file_data = rego_file.read()
            file_data_lines = file_data.splitlines()

            file_data_dict = {}
            rule_count = 1
            current_rule = None
            for data in file_data_lines:
                if data.startswith("# PR-GCP-GDF"):
                    current_rule = data.strip()[2:]
                    file_data_dict[current_rule] = []
                if current_rule:
                    file_data_dict[current_rule].append(data)
            for key, value in file_data_dict.items():
                resource_types = []
                metadata_start_line = None
                for line in value:
                    line = line.strip()
                    if line.startswith("gc_issue"):
                        eval_rule_name = line.split("gc_issue[")[-1][1:-2]
                    
                    if line.startswith("lower(resource.type) =="):
                        resource_types.append(line.split("==")[-1].strip()[1:-1])
                
                for line_number, line in enumerate(value):
                    line = line.strip()
                    if line.startswith(eval_rule_name+"_metadata"):
                        metadata_start_line = line_number
                        break
                end_index = value[::-1].index("}")
                if end_index:
                    metadata = value[metadata_start_line: -end_index]
                else:
                    metadata = value[metadata_start_line: ]
                metadata[0] = "{"
                metadata = "\n".join(metadata)
                print(metadata)
                metdata_dict = json.loads(metadata)
                master_test_id = "TEST_"+file_name.split(".")[0].upper()+"_"+str(rule_count)
                rule_count += 1
                master_snapshot_id = ["GDF_TEMPLATE_SNAPSHOT"]
                rule_type = "rego"
                rule = "file({})".format(file_name)
                evals = [{
                    "id": key,
                    "eval": "data.rule."+eval_rule_name,
                    "message": "data.rule."+eval_rule_name+"_err",
                    "remediationDescription": "make sure you are following the deployment template format at this URL: "+metdata_dict["Resource Help URL"],
                    "remediationFunction": "_".join(key.split("-"))+".py"
                }]
                severity = "Medium"
                title = metdata_dict["Policy Title"]
                description = metdata_dict["Policy Description"]
                tags = [{
                    "cloud": "git",
                    "compliance": [],
                    "service": ["deploymentmanager"]
                }]


                cases.append({
                    "masterTestId": master_test_id,
                    "masterSnapshotId": master_snapshot_id,
                    "type": rule_type,
                    "rule": rule,
                    "evals": evals,
                    "severity": severity,
                    "title": title,
                    "description": description,
                    "tags": tags,
                    "resourceTypes": list(set(resource_types))
                })


testSet["masterTestName"] = "Google_iac_TEST"
testSet["version"] = "0.1"
testSet["cases"] = cases

output = {
    "testSet": [testSet]
}

with open("master-compliance-test-new.json", "w") as mc_file:
    mc_file.write(json.dumps(output))


with open("master-compliance-test.json", "r") as old_mct:
    old_mct_json = json.loads(old_mct.read())

new_mct_json = output

old_mct_cases = old_mct_json["testSet"][0]["cases"]
new_mct_cases = new_mct_json["testSet"][0]["cases"]

for old_case in old_mct_cases:
    old_eval = old_case["evals"][0]["eval"]
    for new_case in new_mct_cases:
        new_eval = new_case["evals"][0]["eval"]

        if old_eval == new_eval:
            new_case["severity"] = old_case["severity"]
            new_case["tags"][0]["compliance"] = old_case["tags"][0]["compliance"]

with open("master-compliance-test-new.json", "w") as test:
    test.write(json.dumps(new_mct_json))