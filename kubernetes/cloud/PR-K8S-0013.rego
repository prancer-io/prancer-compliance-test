package rule

#
# PR-K8S-0013
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "podsecuritypolicy"
    input.spec.hostPID == true
}

rulepass {
    lower(input.kind) == "podsecuritypolicy"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0013: Minimize the admission of containers wishing to share the host process ID namespace (PSP)" {
    k8s_issue["rulepass"]
}
