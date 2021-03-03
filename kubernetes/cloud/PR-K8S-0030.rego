package rule

#
# PR-K8S-0030
#

default rulepass = null

k8s_issue["rulepass"] {
    input.metadata.namespace == "default"
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0030: The default namespace should not be used" {
    k8s_issue["rulepass"]
}
