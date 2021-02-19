package rule

#
# PR-K8S-0022
#

default rulepass = null

k8s_issue["rulepass"] {
    input.spec.containers[_].name == "kube-apiserver"
    input.metadata.namespace == "kube-system"
    input.spec.containers[_].command[_] == "--profiling=true"
}

k8s_issue["rulepass"] {
    input.spec.containers[_].name == "kube-apiserver"
    input.metadata.namespace == "kube-system"
    count([
        c | regex.match("--profiling=.*", input.spec.containers[_].command[_]);
        c := 1]) == 0
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0022: Disable profiling, if not needed. Profiling allows for the identification of specific performance bottlenecks. It generates a significant amount of program data that could potentially be exploited to uncover system and program details. If you are not experiencing any bottlenecks and do not need the profiler for troubleshooting purposes, it is recommended to turn it off to reduce the potential attack surface." {
    k8s_issue["rulepass"]
}
