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

rulepass_err = "PR-K8S-0030: Kubernetes provides a default namespace, where objects are placed if no namespace is specified for them. Placing objects in this namespace makes application of RBAC and other controls more difficult." {
    k8s_issue["rulepass"]
}
