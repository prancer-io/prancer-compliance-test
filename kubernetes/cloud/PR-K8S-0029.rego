package rule

#
# PR-K8S-0029
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "pod"
    input.spec.containers[_].name == "kube-scheduler"
    input.metadata.namespace == "kube-system"
    input.spec.containers[_].command[_] == "--profiling=true"
}

k8s_issue["rulepass"] {
    lower(input.kind) == "pod"
    input.spec.containers[_].name == "kube-scheduler"
    input.metadata.namespace == "kube-system"
    count([
        c | regex.match("--profiling=.*", input.spec.containers[_].command[_]);
        c := 1]) == 0
}

rulepass {
    lower(input.kind) == "pod"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0029: Ensure that the --profiling argument is set to false (Scheduler)" {
    k8s_issue["rulepass"]
}
