package rule

#
# PR-K8S-0061
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "pod"
    input.spec.containers[_].name == "kube-apiserver"
    input.metadata.namespace == "kube-system"
    count([
        c | regex.match("--audit-log-maxbackup=.*", input.spec.containers[_].command[_]);
        c := 1]) == 0
}

k8s_issue["rulepass"] {
    lower(input.kind) == "pod"
    input.spec.containers[_].name == "kube-apiserver"
    input.metadata.namespace == "kube-system"
    regex.match("--audit-log-maxbackup=[0-9]$", input.spec.containers[_].command[_])
}

rulepass {
    lower(input.kind) == "pod"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0061: Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate (API Server)" {
    k8s_issue["rulepass"]
}

k8s_issue_metadata := {
    "Policy Code": "PR-K8S-0061",
    "Type": "Cloud",
    "Product": "Kubernetes",
    "Language": "Cloud",
    "Policy Title": "Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate (API Server) ",
    "Policy Description": "Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate (API Server) ",
    "Resource Type": "pod",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
