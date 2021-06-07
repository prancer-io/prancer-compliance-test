package rule

#
# PR-K8S-0002
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "clusterrole"
    regex.match(".*\\*.*", input.rules[_].resources[_])
}

k8s_issue["rulepass"] {
    lower(input.kind) == "clusterrole"
    regex.match(".*\\*.*", input.rules[_].apiGroups[_])
}

k8s_issue["rulepass"] {
    lower(input.kind) == "clusterrole"
    regex.match(".*\\*.*", input.rules[_].verbs[_])
}

k8s_issue["rulepass"] {
    lower(input.kind) == "role"
    regex.match(".*\\*.*", input.rules[_].resources[_])
}

k8s_issue["rulepass"] {
    lower(input.kind) == "role"
    regex.match(".*\\*.*", input.rules[_].apiGroups[_])
}

k8s_issue["rulepass"] {
    lower(input.kind) == "role"
    regex.match(".*\\*.*", input.rules[_].verbs[_])
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

rulepass_err = "PR-K8S-0002: Minimize wildcard use in Roles and ClusterRoles (RBAC)" {
    k8s_issue["rulepass"]
}

k8s_issue_metadata := {
    "Policy Code": "PR-K8S-0002",
    "Type": "Cloud",
    "Product": "Kubernetes",
    "Language": "Cloud",
    "Policy Title": "Minimize wildcard use in Roles and ClusterRoles (RBAC) ",
    "Policy Description": "Minimize wildcard use in Roles and ClusterRoles (RBAC) ",
    "Resource Type": "role",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
