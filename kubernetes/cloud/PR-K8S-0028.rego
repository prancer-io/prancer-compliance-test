package rule

#
# PR-K8S-0028
#

default rulepass = null

k8s_issue["rulepass"] {
    input.spec.containers[_].name == "kube-apiserver"
    input.metadata.namespace == "kube-system"
    count([
        c | regex.match("--anonymous-auth=.*true.*", input.spec.containers[_].command[_]);
        c := 1]) > 0
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0028: Ensure that the --anonymous-auth argument is set to false (API Server)" {
    k8s_issue["rulepass"]
}
