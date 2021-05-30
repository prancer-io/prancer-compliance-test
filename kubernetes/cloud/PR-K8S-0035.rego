package rule

#
# PR-K8S-0035
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "serviceaccount"
    input.automountServiceAccountToken == true
}

rulepass {
    lower(input.kind) == "serviceaccount"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0035: Ensure that Service Account Tokens are only mounted where necessary (RBAC)" {
    k8s_issue["rulepass"]
}

k8s_issue_metadata := {
    "Policy Code": "PR-K8S-0035",
    "Type": "Cloud",
    "Product": "Kubernetes",
    "Language": "Cloud",
    "Policy Title": "Ensure that Service Account Tokens are only mounted where necessary (RBAC) ",
    "Policy Description": "Ensure that Service Account Tokens are only mounted where necessary (RBAC) ",
    "Resource Type": "serviceaccount",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
