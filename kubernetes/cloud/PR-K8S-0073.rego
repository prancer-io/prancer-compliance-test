package rule

#
# PR-K8S-0073
#

default rulepass = null

k8s_issue["rulepass"] {
    input.spec.containers[_].name == "etcd"
    input.metadata.namespace == "kube-system"
    regex.match("--auto-tls=true", input.spec.containers[_].command[_])
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0073: Ensure that the --auto-tls argument is not set to true (etcd)" {
    k8s_issue["rulepass"]
}
