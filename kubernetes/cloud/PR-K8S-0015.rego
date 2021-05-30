package rule

#
# PR-K8S-0015
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "pod"
    input.spec.containers[_].securityContext.runAsNonRoot == false
}

k8s_issue["rulepass"] {
    lower(input.kind) == "pod"
    input.spec.containers[_].securityContext.runAsUser == 0
}

rulepass {
    lower(input.kind) == "pod"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0015: Do not generally permit containers to be run as the root user." {
    k8s_issue["rulepass"]
}

k8s_issue_metadata := {
    "Policy Code": "PR-K8S-0015",
    "Type": "Cloud",
    "Product": "Kubernetes",
    "Language": "Cloud",
    "Policy Title": "Do not generally permit containers to be run as the root user. ",
    "Policy Description": "Do not generally permit containers to be run as the root user. ",
    "Resource Type": "pod",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
