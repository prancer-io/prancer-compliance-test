package rule

#
# PR-K8S-0027
#

default rulepass = null

k8s_issue["rulepass"] {
    input.spec.containers[_].name == "kube-apiserver"
    input.metadata.namespace == "kube-system"
    count([
        c | regex.match("--authorization-mode=.*RBAC.*", input.spec.containers[_].command[_]);
        c := 1]) == 0
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0027: Turn on Role Based Access Control. Role Based Access Control (RBAC) allows fine-grained control over the operations that different entities can perform on different objects in the cluster. It is recommended to use the RBAC authorisation mode." {
    k8s_issue["rulepass"]
}
