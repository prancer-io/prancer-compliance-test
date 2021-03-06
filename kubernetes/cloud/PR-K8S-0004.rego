package rule

#
# PR-K8S-0004
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "rolebinding"
    lower(input.roleRef.kind) == "role"
    lower(input.roleRef.name) == "cluster-admin"
}

k8s_issue["rulepass"] {
    lower(input.kind) == "clusterrolebinding"
    lower(input.roleRef.kind) == "role"
    lower(input.roleRef.name) == "cluster-admin"
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

rulepass_err = "PR-K8S-0004: Ensure that the cluster-admin role is only used where required (RBAC)" {
    k8s_issue["rulepass"]
}

k8s_issue_metadata := {
    "Policy Code": "PR-K8S-0004",
    "Type": "Cloud",
    "Product": "Kubernetes",
    "Language": "Cloud",
    "Policy Title": "Ensure that the cluster-admin role is only used where required (RBAC) ",
    "Policy Description": "Ensure that the cluster-admin role is only used where required (RBAC) ",
    "Resource Type": "rolebinding",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
