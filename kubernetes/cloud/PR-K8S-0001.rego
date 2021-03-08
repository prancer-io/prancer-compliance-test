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

rulepass {
    lower(input.kind) == "clusterrole"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0001: Minimize access to secrets (RBAC)" {
    k8s_issue["rulepass"]
}
