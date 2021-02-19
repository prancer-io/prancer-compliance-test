package rule

#
# PR-K8S-0034
#

default rulepass = null

k8s_issue["rulepass"] {
    input.spec.containers[_].name == "kube-controller-manager"
    input.metadata.namespace == "kube-system"
    count([
        c | regex.match("--root-ca-file=.*", input.spec.containers[_].command[_]);
        c := 1]) == 0
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0034: Allow pods to verify the API server's serving certificate before establishing connections. Processes running within pods that need to contact the API server must verify the API server's serving certificate. Failing to do so could be a subject to man-in-the-middle attacks." {
    k8s_issue["rulepass"]
}
