package rule

#
# PR-K8S-0024
#

default rulepass = null

k8s_issue["rulepass"] {
    input.spec.containers[_].name == "kube-apiserver"
    input.metadata.namespace == "kube-system"
    count([
        c | regex.match("--kubelet-certificate-authority=.*", input.spec.containers[_].command[_]);
        c := 1]) == 0
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0024: Ensure that the --kubelet-certificate-authority argument is set as appropriate (API Server)" {
    k8s_issue["rulepass"]
}
