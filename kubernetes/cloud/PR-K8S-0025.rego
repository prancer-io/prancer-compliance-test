package rule

#
# PR-K8S-0025
#

default rulepass = null

k8s_issue["rulepass"] {
    input.spec.containers[_].name == "kube-apiserver"
    input.metadata.namespace == "kube-system"
    count([
        c | regex.match("--kubelet-client-certificate=.*", input.spec.containers[_].command[_]);
        c := 1]) == 0
}

k8s_issue["rulepass"] {
    input.spec.containers[_].name == "kube-apiserver"
    input.metadata.namespace == "kube-system"
    count([
        c | regex.match("--kubelet-client-key=.*", input.spec.containers[_].command[_]);
        c := 1]) == 0
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0025: Enable certificate based kubelet authentication. The apiserver, by default, does not authenticate itself to the kubelet's HTTPS endpoints. The requests from the apiserver are treated anonymously. You should set up certificate-based kubelet authentication to ensure that the apiserver authenticates itself to kubelets when submitting requests." {
    k8s_issue["rulepass"]
}
