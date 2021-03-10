package rule

#
# PR-K8S-0062
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "pod"
    input.spec.containers[_].name == "kube-apiserver"
    input.metadata.namespace == "kube-system"
    count([
        c | regex.match("--audit-log-maxsize=.*", input.spec.containers[_].command[_]);
        c := 1]) == 0
}

k8s_issue["rulepass"] {
    lower(input.kind) == "pod"
    input.spec.containers[_].name == "kube-apiserver"
    input.metadata.namespace == "kube-system"
    regex.match("--audit-log-maxsize=([0-9]|[0-9][0-9])$", input.spec.containers[_].command[_])
}

rulepass {
    lower(input.kind) == "pod"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0062: Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate (API Server)" {
    k8s_issue["rulepass"]
}
