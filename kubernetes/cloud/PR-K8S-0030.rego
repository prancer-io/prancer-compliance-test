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
