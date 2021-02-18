package rule

#
# PR-K8S-0011
#

default rulepass = null

k8s_issue["rulepass"] {
    input.spec.hostIPC == true
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0011: Minimize the admission of containers wishing to share the host IPC namespace (PSP)" {
    k8s_issue["rulepass"]
}
