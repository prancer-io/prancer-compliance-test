package rule

#
# PR-K8S-0028
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "pod"
    input.spec.containers[_].name == "kube-apiserver"
    input.metadata.namespace == "kube-system"
    count([
        c | regex.match("--anonymous-auth=.*true.*", input.spec.containers[_].command[_]);
        c := 1]) > 0
}

rulepass {
    lower(input.kind) == "pod"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0028: Ensure that the --anonymous-auth argument is set to false (API Server)" {
    k8s_issue["rulepass"]
}

k8s_issue_metadata := {
    "Policy Code": "PR-K8S-0028",
    "Type": "Cloud",
    "Product": "Kubernetes",
    "Language": "Cloud",
    "Policy Title": "Ensure that the --anonymous-auth argument is set to false (API Server) ",
    "Policy Description": "Ensure that the --anonymous-auth argument is set to false (API Server) ",
    "Resource Type": "pod",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
