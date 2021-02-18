package rule

#
# PR-K8S-0012
#

default rulepass = null

k8s_issue["rulepass"] {
    input.spec.hostNetwork == true
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0012: Minimize the admission of containers wishing to share the host network namespace (PSP)" {
    k8s_issue["rulepass"]
}
