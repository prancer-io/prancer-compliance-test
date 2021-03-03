package rule

#
# PR-K8S-0067
#

default rulepass = null

k8s_issue["rulepass"] {
    input.spec.containers[_].name == "kube-controller-manager"
    input.metadata.namespace == "kube-system"
    count([
        c | regex.match("--feature-gates=.*RotateKubeletServerCertificate=true.*", input.spec.containers[_].command[_]);
        c := 1]) == 0
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0067: Ensure that the RotateKubeletServerCertificate argument is set to true (Controller Manager)" {
    k8s_issue["rulepass"]
}
