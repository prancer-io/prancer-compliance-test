package rule

#
# PR-K8S-0041
#

default rulepass = null

k8s_issue["rulepass"] {
    count(input.spec.ingress) == 0
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0041: Ensure that the admission control plugin EventRateLimit is set (API Server)" {
    k8s_issue["rulepass"]
}
