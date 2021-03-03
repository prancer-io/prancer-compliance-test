package rule

#
# PR-K8S-0069
#

default rulepass = null

k8s_issue["rulepass"] {
    input.spec.containers[_].name == "kube-apiserver"
    input.metadata.namespace == "kube-system"
    regex.match("--kubelet-https=false", input.spec.containers[_].command[_])
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0069: Ensure that the --kubelet-https argument is set to true (API Server)" {
    k8s_issue["rulepass"]
}
