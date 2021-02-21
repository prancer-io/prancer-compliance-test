package rule

#
# PR-K8S-0063
#

default rulepass = null

k8s_issue["rulepass"] {
    input.spec.containers[_].name == "kube-apiserver"
    input.metadata.namespace == "kube-system"
    regex.match("--feature-gates=.*AdvancedAuditing=false.*", input.spec.containers[_].command[_])
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0063: Ensure that the AdvancedAuditing argument is not set to false (API Server)" {
    k8s_issue["rulepass"]
}
