package rule

#
# PR-K8S-0057
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "pod"
    input.metadata.namespace != "kube-system"
    count(input.spec.volumes[_].hostPath) > 0
}

rulepass {
    lower(input.kind) == "pod"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0057: Ensure pods outside of kube-system do not have access to node volume" {
    k8s_issue["rulepass"]
}

k8s_issue_metadata := {
    "Policy Code": "PR-K8S-0057",
    "Type": "Cloud",
    "Product": "Kubernetes",
    "Language": "Cloud",
    "Policy Title": "Ensure pods outside of kube-system do not have access to node volume ",
    "Policy Description": "Ensure pods outside of kube-system do not have access to node volume ",
    "Resource Type": "pod",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
