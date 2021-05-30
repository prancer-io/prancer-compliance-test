package rule

#
# PR-K8S-0003-DCL
#

default default_role = null

k8s_issue["default_role"] {
    lower(input.kind) == "clusterrolebinding"
    lower(input.roleRef.kind) == "role"
    lower(input.roleRef.name) == "default"
}

k8s_issue["default_role"] {
    lower(input.kind) == "rolebinding"
    lower(input.roleRef.kind) == "role"
    lower(input.roleRef.name) == "default"
}

default_role {
    lower(input.kind) == "clusterrolebinding"
    not k8s_issue["default_role"]
}

default_role {
    lower(input.kind) == "rolebinding"
    not k8s_issue["default_role"]
}

default_role = false {
    k8s_issue["default_role"]
}

default_role_err = "PR-K8S-0003-DCL: Ensure that default service accounts are not actively used. (RBAC)" {
    k8s_issue["default_role"]
}

default_role_metadata := {
    "Policy Code": "PR-K8S-0003-DCL",
    "Type": "IaC",
    "Product": "Kubernetes",
    "Language": "K8s DL",
    "Policy Title": "Ensure that default service accounts are not actively used. (RBAC) ",
    "Policy Description": "Ensure that default service accounts are not actively used. (RBAC) ",
    "Resource Type": "rolebinding",
    "Policy Help URL": "",
    "Resource Help URL": ""
}

#
# PR-K8S-0004-DCL
#

default admin_role = null

k8s_issue["admin_role"] {
    lower(input.kind) == "clusterrolebinding"
    lower(input.roleRef.kind) == "role"
    lower(input.roleRef.name) == "cluster-admin"
}

k8s_issue["admin_role"] {
    lower(input.kind) == "rolebinding"
    lower(input.roleRef.kind) == "role"
    lower(input.roleRef.name) == "cluster-admin"
}

admin_role {
    lower(input.kind) == "clusterrolebinding"
    not k8s_issue["admin_role"]
}

admin_role {
    lower(input.kind) == "rolebinding"
    not k8s_issue["admin_role"]
}

admin_role = false {
    k8s_issue["admin_role"]
}

admin_role_err = "PR-K8S-0004-DCL: Ensure that the cluster-admin role is only used where required (RBAC)" {
    k8s_issue["admin_role"]
}

admin_role_metadata := {
    "Policy Code": "PR-K8S-0003-DCL",
    "Type": "IaC",
    "Product": "Kubernetes",
    "Language": "K8s DL",
    "Policy Title": "Ensure that default service accounts are not actively used. (RBAC) ",
    "Policy Description": "Ensure that default service accounts are not actively used. (RBAC) ",
    "Resource Type": "rolebinding",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
