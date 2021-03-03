package rule

#
# PR-K8S-0057
#

default rulepass = null

k8s_issue["rulepass"] {
    input.metadata.namespace != "kube-system"
    count(input.spec.volumes[_].hostPath) > 0
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0057: Ensure pods outside of kube-system do not have access to node volume" {
    k8s_issue["rulepass"]
}
