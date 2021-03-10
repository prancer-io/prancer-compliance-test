package rule

#
# PR-K8S-0053
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "pod"
    input.spec.containers[_].name == "kube-controller-manager"
    input.metadata.namespace == "kube-system"
    regex.match("--address=.*", input.spec.containers[_].command[_])
    count([
        c | regex.match("--address=127.0.0.1", input.spec.containers[_].command[_]);
        c := 1]) == 0
}

rulepass {
    lower(input.kind) == "pod"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0053: Ensure that the --address argument is set to 127.0.0.1 (Controller Manager)" {
    k8s_issue["rulepass"]
}
