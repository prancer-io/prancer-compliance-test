package rule

#
# PR-K8S-0046
#

default rulepass = null

k8s_issue["rulepass"] {
    input.spec.containers[_].name == "kube-apiserver"
    input.metadata.namespace == "kube-system"
    regex.match("--disable-admission-plugins=.*", input.spec.containers[_].command[_])
    count([
        c | regex.match("--disable-admission-plugins=.*NamespaceLifecycle.*", input.spec.containers[_].command[_]);
        c := 1]) == 0
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0046: Ensure that the admission control plugin NamespaceLifecycle is set (API Server)" {
    k8s_issue["rulepass"]
}
