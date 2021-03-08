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
    lower(input.kind) == ""
    regex.match(".*\\*.*", input.rules[_].verbs[_])
}

rulepass {
    lower(input.kind) == "clusterrole"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0002: Minimize wildcard use in Roles and ClusterRoles (RBAC)" {
    k8s_issue["rulepass"]
}
