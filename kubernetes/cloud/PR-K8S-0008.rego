package rule

#
# PR-K8S-0008
#

default rulepass = null

k8s_issue["rulepass"] {
    input.spec.privileged
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0008: Minimize the admission of privileged containers (PSP)" {
    k8s_issue["rulepass"]
}
