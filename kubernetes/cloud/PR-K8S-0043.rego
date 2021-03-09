package rule

#
# PR-K8S-0043
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "pod"
    input.spec.containers[_].name == "kube-apiserver"
    input.metadata.namespace == "kube-system"
    regex.match("--secure-port=0", input.spec.containers[_].command[_])
}

rulepass {
    lower(input.kind) == "pod"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0043: Ensure that the --secure-port argument is not set to 0 (API Server)" {
    k8s_issue["rulepass"]
}
