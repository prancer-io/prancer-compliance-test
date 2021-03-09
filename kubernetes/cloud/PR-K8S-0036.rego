package rule

#
# PR-K8S-0036
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "networkpolicy"
    count(input.spec.ingress) == 0
}

rulepass {
    lower(input.kind) == "networkpolicy"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0036: Restrict Traffic Among Pods with a Network Policy" {
    k8s_issue["rulepass"]
}
