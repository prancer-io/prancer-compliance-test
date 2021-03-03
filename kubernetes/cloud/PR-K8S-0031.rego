package rule

#
# PR-K8S-0031
#

default rulepass = null

k8s_issue["rulepass"] {
    input.spec.containers[_].name == "kube-controller-manager"
    input.metadata.namespace == "kube-system"
    count([
        c | regex.match("--terminated-pod-gc-threshold=.*", input.spec.containers[_].command[_]);
        c := 1]) == 0
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0031: Ensure that the --terminated-pod-gc-threshold argument is set as appropriate (Controller Manager)" {
    k8s_issue["rulepass"]
}
