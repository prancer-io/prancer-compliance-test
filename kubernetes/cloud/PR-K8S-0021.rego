package rule

#
# PR-K8S-0021
#

default rulepass = null

k8s_issue["rulepass"] {
    count([
        c | regex.match("seccomp.security.alpha.kubernetes.io\/pod.*", input.metadata.annotations[_]);
        c := 1]) == 0
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0021: Enable runtime/default seccomp profile in your pod definitions. Seccomp (secure computing mode) is used to restrict the set of system calls applications can make, allowing cluster administrators greater control over the security of workloads running in the cluster. Kubernetes disables seccomp profiles by default for historical reasons. You should enable it to ensure that the workloads have restricted actions available within the container." {
    k8s_issue["rulepass"]
}
