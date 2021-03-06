package rule

#
# PR-K8S-0073
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "pod"
    input.spec.containers[_].name == "etcd"
    input.metadata.namespace == "kube-system"
    regex.match("--auto-tls=true", input.spec.containers[_].command[_])
}

rulepass {
    lower(input.kind) == "pod"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0073: Ensure that the --auto-tls argument is not set to true (etcd)" {
    k8s_issue["rulepass"]
}

k8s_issue_metadata := {
    "Policy Code": "PR-K8S-0073",
    "Type": "Cloud",
    "Product": "Kubernetes",
    "Language": "Cloud",
    "Policy Title": "Ensure that the --auto-tls argument is not set to true (etcd) ",
    "Policy Description": "Ensure that the --auto-tls argument is not set to true (etcd) ",
    "Resource Type": "pod",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
