package rule

#
# PR-K8S-0003
#

default default_role = null

k8s_issue["default_role"] {
    lower(input.roleRef.kind) == "role"
    lower(input.roleRef.name) == "default"
}

default_role {
    not k8s_issue["default_role"]
}

default_role = false {
    k8s_issue["default_role"]
}

default_role_err = "PR-K8S-0003: Ensure that default service accounts are not actively used. (RBAC)" {
    k8s_issue["default_role"]
}
