package rule

#
# PR-K8S-0001-DCL
#

default rbac_secrets = null

k8s_issue["rbac_secrets"] {
    lower(input.kind) == "clusterrole"
    input.rules[_].resources[_] == "secrets"
}

k8s_issue["rbac_secrets"] {
    lower(input.kind) == "clusterrole"
    regex.match(".*\\*.*", input.rules[_].resources[_])
}

k8s_issue["rbac_secrets"] {
    lower(input.kind) == "role"
    input.rules[_].resources[_] == "secrets"
}

k8s_issue["rbac_secrets"] {
    lower(input.kind) == "role"
    regex.match(".*\\*.*", input.rules[_].resources[_])
}

rbac_secrets {
    lower(input.kind) == "clusterrole"
    not k8s_issue["rbac_secrets"]
}

rbac_secrets {
    lower(input.kind) == "role"
    not k8s_issue["rbac_secrets"]
}

rbac_secrets = false {
    k8s_issue["rbac_secrets"]
}

rbac_secrets_err = "PR-K8S-0001-DCL: Minimize access to secrets (RBAC)" {
    k8s_issue["rbac_secrets"]
}

#
# PR-K8S-0002-DCL
#

default rbac_wildcard = null

k8s_issue["rbac_wildcard"] {
    lower(input.kind) == "clusterrole"
    regex.match(".*\\*.*", input.rules[_].resources[_])
}

k8s_issue["rbac_wildcard"] {
    lower(input.kind) == "clusterrole"
    regex.match(".*\\*.*", input.rules[_].apiGroups[_])
}

k8s_issue["rbac_wildcard"] {
    lower(input.kind) == "clusterrole"
    regex.match(".*\\*.*", input.rules[_].verbs[_])
}

k8s_issue["rbac_wildcard"] {
    lower(input.kind) == "role"
    regex.match(".*\\*.*", input.rules[_].resources[_])
}

k8s_issue["rbac_wildcard"] {
    lower(input.kind) == "role"
    regex.match(".*\\*.*", input.rules[_].apiGroups[_])
}

k8s_issue["rbac_wildcard"] {
    lower(input.kind) == "role"
    regex.match(".*\\*.*", input.rules[_].verbs[_])
}

rbac_wildcard {
    lower(input.kind) == "clusterrole"
    not k8s_issue["rbac_wildcard"]
}

rbac_wildcard {
    lower(input.kind) == "role"
    not k8s_issue["rbac_wildcard"]
}

rbac_wildcard = false {
    k8s_issue["rbac_wildcard"]
}

rbac_wildcard_err = "PR-K8S-0002-DCL: Minimize wildcard use in Roles and ClusterRoles (RBAC)" {
    k8s_issue["rbac_wildcard"]
}
