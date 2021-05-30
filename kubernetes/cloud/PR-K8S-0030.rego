package rule

#
# PR-K8S-0030
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "pod"
    input.metadata.namespace == "default"
}

rulepass {
    lower(input.kind) == "pod"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0030: The default namespace should not be used" {
    k8s_issue["rulepass"]
}

k8s_issue_metadata := {
    "Policy Code": "PR-K8S-0030",
    "Type": "Cloud",
    "Product": "Kubernetes",
    "Language": "Cloud",
    "Policy Title": "The default namespace should not be used ",
    "Policy Description": "The default namespace should not be used ",
    "Resource Type": "pod",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
