package rule

#
# PR-K8S-0035
#

default rulepass = null

k8s_issue["rulepass"] {
    input.automountServiceAccountToken == true
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0035: Ensure that Service Account Tokens are only mounted where necessary (RBAC)" {
    k8s_issue["rulepass"]
}
