package rule

#
# PR-K8S-0084
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "pod"
    container := input.spec.containers[_]
    not container.securityContext.seLinuxOptions
}

rulepass {
    lower(input.kind) == "pod"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0084: Apply Security Context to Your Pods and Containers" {
    k8s_issue["rulepass"]
}

k8s_issue_metadata := {
    "Policy Code": "PR-K8S-0084",
    "Type": "Cloud",
    "Product": "Kubernetes",
    "Language": "Cloud",
    "Policy Title": "Apply Security Context to Your Pods and Containers ",
    "Policy Description": "Apply Security Context to Your Pods and Containers ",
    "Resource Type": "pod",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
