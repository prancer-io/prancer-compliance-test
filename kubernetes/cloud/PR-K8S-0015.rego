package rule

#
# PR-K8S-0015
#

default rulepass = null

k8s_issue["rulepass"] {
    input.spec.containers[_].securityContext.runAsNonRoot == false
}

k8s_issue["rulepass"] {
    input.spec.containers[_].securityContext.runAsUser == 0
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0015: Do not generally permit containers to be run as the root user." {
    k8s_issue["rulepass"]
}
