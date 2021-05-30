package rule

#
# PR-K8S-0014
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "podsecuritypolicy"
    input.spec.hostPID == true
}

rulepass {
    lower(input.kind) == "podsecuritypolicy"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0014: Minimize the admission of containers with allowPrivilegeEscalation (PSP)" {
    k8s_issue["rulepass"]
}

k8s_issue_metadata := {
    "Policy Code": "PR-K8S-0014",
    "Type": "Cloud",
    "Product": "Kubernetes",
    "Language": "Cloud",
    "Policy Title": "Minimize the admission of containers with allowPrivilegeEscalation (PSP) ",
    "Policy Description": "Minimize the admission of containers with allowPrivilegeEscalation (PSP) ",
    "Resource Type": "podsecuritypolicy",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
