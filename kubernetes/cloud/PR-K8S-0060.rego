package rule

#
# PR-K8S-0060
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "pod"
    input.spec.containers[_].name == "kube-apiserver"
    input.metadata.namespace == "kube-system"
    count([
        c | regex.match("--audit-log-maxage=.*", input.spec.containers[_].command[_]);
        c := 1]) == 0
}

k8s_issue["rulepass"] {
    lower(input.kind) == "pod"
    input.spec.containers[_].name == "kube-apiserver"
    input.metadata.namespace == "kube-system"
    regex.match("--audit-log-maxage=([0-9]|[0-2][0-9])$", input.spec.containers[_].command[_])
}

rulepass {
    lower(input.kind) == "pod"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0060: Ensure that the --audit-log-maxage argument is set to 30 or as appropriate (API Server)" {
    k8s_issue["rulepass"]
}
