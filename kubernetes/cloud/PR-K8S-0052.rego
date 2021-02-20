package rule

#
# PR-K8S-0052
#

default rulepass = null

k8s_issue["rulepass"] {
    input.spec.containers[_].name == "kube-scheduler"
    input.metadata.namespace == "kube-system"
    regex.match("--address=.*", input.spec.containers[_].command[_])
    count([
        c | regex.match("--address=127.0.0.1", input.spec.containers[_].command[_]);
        c := 1]) == 0
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0052: Ensure that the --address argument is set to 127.0.0.1 (Scheduler)" {
    k8s_issue["rulepass"]
}
