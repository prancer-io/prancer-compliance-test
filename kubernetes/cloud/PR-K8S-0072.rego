package rule

#
# PR-K8S-0072
#

default rulepass = null

k8s_issue["rulepass"] {
    input.spec.containers[_].name == "etcd"
    input.metadata.namespace == "kube-system"
    count([
        c | regex.match("--client-cert-auth=true", input.spec.containers[_].command[_]);
        c := 1]) == 0
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0072: Ensure that the --client-cert-auth argument is set to true (etcd)" {
    k8s_issue["rulepass"]
}
