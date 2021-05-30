package rule

#
# PR-K8S-0001
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "clusterrole"
    input.rules[_].resources[_] == "secrets"
}

k8s_issue["rulepass"] {
    lower(input.kind) == "clusterrole"
    regex.match(".*\\*.*", input.rules[_].resources[_])
}

k8s_issue["rulepass"] {
    lower(input.kind) == "role"
    input.rules[_].resources[_] == "secrets"
}

k8s_issue["rulepass"] {
    lower(input.kind) == "role"
    regex.match(".*\\*.*", input.rules[_].resources[_])
}

rulepass {
    lower(input.kind) == "clusterrole"
    not k8s_issue["rulepass"]
}

rulepass {
    lower(input.kind) == "role"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0001: Minimize access to secrets (RBAC)" {
    k8s_issue["rulepass"]
}

k8s_issue_metadata := {
    "Policy Code": "PR-K8S-0001",
    "Type": "Cloud",
    "Product": "Kubernetes",
    "Language": "Cloud",
    "Policy Title": "Minimize access to secrets (RBAC) ",
    "Policy Description": "Minimize access to secrets (RBAC) ",
    "Resource Type": "role",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
