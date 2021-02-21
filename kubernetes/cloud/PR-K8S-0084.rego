package rule

#
# PR-K8S-0084
#

default rulepass = null

k8s_issue["rulepass"] {
    container := input.spec.containers[_]
    not container.securityContext.seLinuxOptions
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0084: Apply Security Context to Your Pods and Containers" {
    k8s_issue["rulepass"]
}
