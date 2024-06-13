package rule

# Common function to extract policy names
policy_names(policy_type) = {name |
    policy := input.policies[_]
    lower(policy.name) == policy_type
    name = lower(policy.attributes.name)
}

# Common function to check if a policy is used in proxies or targets
policy_used_in_flows(policy_set, entity_type) {
    entity := input[entity_type][_]
    policy_name := policy_set[_]
    contains_policy(entity, policy_name)
}

# Helper function to check if an element contains the policy
contains_policy(element, policy_name) {
    flow := element.children[_]
    request_or_response := flow.children[_]
    step := request_or_response.children[_]
    step.name == "Step"
    name := step.children[_]
    name.name == "Name"
    lower(name.text) == policy_name
}

# PR-GCP-CLD-APG-001
default spike_arrest = null

gc_issue["spike_arrest"] {
    count([c| lower(input.policies[_].name) == "spikearrest"; c:=1]) == 0
}

gc_issue["spike_arrest_usage_in_proxy_flows"] {
    not policy_used_in_flows(policy_names("spikearrest"), "proxies")
}

gc_issue["spike_arrest_usage_in_target_flows"] {
    not policy_used_in_flows(policy_names("spikearrest"), "targets")
}

spike_arrest {
    not gc_issue["spike_arrest"]
    not gc_issue["spike_arrest_usage_in_proxy_flows"]
} {
    not gc_issue["spike_arrest"]
    not gc_issue["spike_arrest_usage_in_target_flows"]
}

spike_arrest = false {
    gc_issue["spike_arrest"]
} { 
    gc_issue["spike_arrest_usage_in_proxy_flows"] 
    gc_issue["spike_arrest_usage_in_target_flows"]
}

spike_arrest_err = "Spike arrest policy not added in Apigee or not used in any flow" {
    gc_issue["spike_arrest"]
} {
    gc_issue["spike_arrest_usage_in_proxy_flows"] 
    gc_issue["spike_arrest_usage_in_target_flows"]
}

spike_arrest_metadata := {
    "Policy Code": "PR-GCP-CLD-APG-001",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Spike arrest policy not added in Apigee",
    "Policy Description": "",
    "Resource Type": "iam.v1.projects",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects"
}

# PR-GCP-CLD-APG-002
default json_threat_protection = null

gc_issue["json_threat_protection"] {
    count([c| lower(input.policies[_].name) == "jsonthreatprotection"; c:=1]) == 0
}

gc_issue["json_threat_protection_usage_in_proxy_flows"] {
    not policy_used_in_flows(policy_names("jsonthreatprotection"), "proxies")
}

gc_issue["json_threat_protection_usage_in_target_flows"] {
    not policy_used_in_flows(policy_names("jsonthreatprotection"), "targets")
}

json_threat_protection {
    not gc_issue["json_threat_protection"]
    not gc_issue["json_threat_protection_usage_in_proxy_flows"]
} {
    not gc_issue["json_threat_protection"]
    not gc_issue["json_threat_protection_usage_in_target_flows"]
}

json_threat_protection = false {
    gc_issue["json_threat_protection"]
} {
    gc_issue["json_threat_protection_usage_in_proxy_flows"]
    gc_issue["json_threat_protection_usage_in_target_flows"]
}

json_threat_protection_err = "JSON Threat Protection policy not added in Apigee or not used in any flow" {
    gc_issue["json_threat_protection"]
} {
    gc_issue["json_threat_protection_usage_in_proxy_flows"]
    gc_issue["json_threat_protection_usage_in_target_flows"]
}

json_threat_protection_metadata := {
    "Policy Code": "PR-GCP-CLD-APG-002",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "JSON Threat Protection policy not added in Apigee",
    "Policy Description": "",
    "Resource Type": "iam.v1.projects",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects"
}

# PR-GCP-CLD-APG-003
default xml_threat_protection = null

gc_issue["xml_threat_protection"] {
    count([c | lower(input.policies[_].name) == "xmlthreatprotection"; c := 1]) == 0
}

gc_issue["xml_threat_protection_usage_in_proxy_flows"] {
    not policy_used_in_flows(policy_names("xmlthreatprotection"), "proxies")
}

gc_issue["xml_threat_protection_usage_in_target_flows"] {
    not policy_used_in_flows(policy_names("xmlthreatprotection"), "targets")
}

xml_threat_protection {
    not gc_issue["xml_threat_protection"]
    not gc_issue["xml_threat_protection_usage_in_proxy_flows"]
} {
    not gc_issue["xml_threat_protection"]
    not gc_issue["xml_threat_protection_usage_in_target_flows"]
}

xml_threat_protection = false {
    gc_issue["xml_threat_protection"]
} {
    gc_issue["xml_threat_protection_usage_in_proxy_flows"]
    gc_issue["xml_threat_protection_usage_in_target_flows"]
}

xml_threat_protection_err = "XML Threat Protection policy not added in Apigee or not used in any flow" {
    gc_issue["xml_threat_protection"]
} {
    gc_issue["xml_threat_protection_usage_in_proxy_flows"]
    gc_issue["xml_threat_protection_usage_in_target_flows"]
}

xml_threat_protection_metadata := {
    "Policy Code": "PR-GCP-CLD-APG-003",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "XML Threat Protection policy not added in Apigee",
    "Policy Description": "",
    "Resource Type": "iam.v1.projects",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects"
}
