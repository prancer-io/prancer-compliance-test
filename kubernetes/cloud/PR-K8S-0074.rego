package rule

#
# PR-K8S-0074
#

default rulepass = null

k8s_issue["rulepass"] {
    input.spec.containers[_].name == "kube-apiserver"
    input.metadata.namespace == "kube-system"
    regex.match("--token-auth-file=.*", input.spec.containers[_].command[_])
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0074: Ensure that the --token-auth-file parameter is not set (API Server)" {
    k8s_issue["rulepass"]
}
