package rule

#
# PR-K8S-0008
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "podsecuritypolicy"
    input.spec.privileged
}

rulepass {
    lower(input.kind) == "podsecuritypolicy"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0008: Minimize the admission of privileged containers (PSP)" {
    k8s_issue["rulepass"]
}

k8s_issue_metadata := {
    "Policy Code": "PR-K8S-0008",
    "Type": "Cloud",
    "Product": "Kubernetes",
    "Language": "Cloud",
    "Policy Title": "Minimize the admission of privileged containers (PSP) ",
    "Policy Description": "Minimize the admission of privileged containers (PSP) ",
    "Resource Type": "podsecuritypolicy",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
