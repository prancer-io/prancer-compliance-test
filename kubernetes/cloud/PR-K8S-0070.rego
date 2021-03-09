package rule

#
# PR-K8S-0070
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "pod"
    input.spec.containers[_].name == "kube-controller-manager"
    input.metadata.namespace == "kube-system"
    count([
        c | regex.match("--service-account-private-key-file=.*", input.spec.containers[_].command[_]);
        c := 1]) == 0
}

rulepass {
    lower(input.kind) == "pod"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0070: Ensure that the --service-account-private-key-file argument is set as appropriate (Controller Manager)" {
    k8s_issue["rulepass"]
}
