package rule

#
# PR-K8S-0018
#

default rulepass = null

k8s_issue["rulepass"] {
    input.spec.containers[_].securityContext.privileged == true
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0018: Ensure that Containers are not running in privileged mode" {
    k8s_issue["rulepass"]
}
