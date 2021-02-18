package rule

#
# PR-K8S-0014
#

default rulepass = null

k8s_issue["rulepass"] {
    input.spec.hostPID == true
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0014: Minimize the admission of containers with allowPrivilegeEscalation (PSP)" {
    k8s_issue["rulepass"]
}
