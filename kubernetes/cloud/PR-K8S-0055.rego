package rule

#
# PR-K8S-0055
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "pod"
    input.spec.containers[_].name == "kube-controller-manager"
    input.metadata.namespace == "kube-system"
    regex.match("--bind-address=.*", input.spec.containers[_].command[_])
    count([
        c | regex.match("--bind-address=127.0.0.1", input.spec.containers[_].command[_]);
        c := 1]) == 0
}

rulepass {
    lower(input.kind) == "pod"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0055: Ensure that the --bind-address argument is set to 127.0.0.1 (Controller Manager)" {
    k8s_issue["rulepass"]
}

k8s_issue_metadata := {
    "Policy Code": "PR-K8S-0055",
    "Type": "Cloud",
    "Product": "Kubernetes",
    "Language": "Cloud",
    "Policy Title": "Ensure that the --bind-address argument is set to 127.0.0.1 (Controller Manager) ",
    "Policy Description": "Ensure that the --bind-address argument is set to 127.0.0.1 (Controller Manager) ",
    "Resource Type": "pod",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
