package rule

#
# PR-K8S-0058
#

default rulepass = null

k8s_issue["rulepass"] {
    input.spec.containers[_].name == "kube-apiserver"
    input.metadata.namespace == "kube-system"
    regex.match("--authorization-mode=.*AlwaysAllow.*", input.spec.containers[_].command[_])
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0058: Ensure that the --authorization-mode argument is not set to AlwaysAllow (API Server)" {
    k8s_issue["rulepass"]
}
