package rule

#
# PR-K8S-0004
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.roleRef.kind) == "role"
    lower(input.roleRef.name) == "cluster-admin"
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0004: Ensure that the cluster-admin role is only used where required (RBAC)" {
    k8s_issue["rulepass"]
}
