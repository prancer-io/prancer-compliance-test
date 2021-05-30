package rule

#
# PR-K8S-0031
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "pod"
    input.spec.containers[_].name == "kube-controller-manager"
    input.metadata.namespace == "kube-system"
    count([
        c | regex.match("--terminated-pod-gc-threshold=.*", input.spec.containers[_].command[_]);
        c := 1]) == 0
}

rulepass {
    lower(input.kind) == "pod"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0031: Ensure that the --terminated-pod-gc-threshold argument is set as appropriate (Controller Manager)" {
    k8s_issue["rulepass"]
}

k8s_issue_metadata := {
    "Policy Code": "PR-K8S-0031",
    "Type": "Cloud",
    "Product": "Kubernetes",
    "Language": "Cloud",
    "Policy Title": "Ensure that the --terminated-pod-gc-threshold argument is set as appropriate (Controller Manager) ",
    "Policy Description": "Ensure that the --terminated-pod-gc-threshold argument is set as appropriate (Controller Manager) ",
    "Resource Type": "pod",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
