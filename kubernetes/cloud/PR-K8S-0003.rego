package rule

#
# PR-K8S-0003
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "rolebinding"
    lower(input.roleRef.kind) == "role"
    lower(input.roleRef.name) == "default"
}

k8s_issue["rulepass"] {
    lower(input.kind) == "clusterrolebinding"
    lower(input.roleRef.kind) == "role"
    lower(input.roleRef.name) == "default"
}

rulepass {
    lower(input.kind) == "rolebinding"
    not k8s_issue["rulepass"]
}

rulepass {
    lower(input.kind) == "clusterrolebinding"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0003: Ensure that default service accounts are not actively used. (RBAC)" {
    k8s_issue["rulepass"]
}

k8s_issue_metadata := {
    "Policy Code": "PR-K8S-0003",
    "Type": "Cloud",
    "Product": "Kubernetes",
    "Language": "Cloud",
    "Policy Title": "Ensure that default service accounts are not actively used. (RBAC) ",
    "Policy Description": "Ensure that default service accounts are not actively used. (RBAC) ",
    "Resource Type": "rolebinding",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
