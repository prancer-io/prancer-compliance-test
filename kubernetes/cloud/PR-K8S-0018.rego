package rule

#
# PR-K8S-0018
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "pod"
    input.spec.containers[_].securityContext.privileged == true
}

rulepass {
    lower(input.kind) == "pod"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0018: Ensure that Containers are not running in privileged mode" {
    k8s_issue["rulepass"]
}

k8s_issue_metadata := {
    "Policy Code": "PR-K8S-0018",
    "Type": "Cloud",
    "Product": "Kubernetes",
    "Language": "Cloud",
    "Policy Title": "Ensure that Containers are not running in privileged mode ",
    "Policy Description": "Ensure that Containers are not running in privileged mode ",
    "Resource Type": "pod",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
