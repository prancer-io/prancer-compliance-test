package rule

#
# PR-K8S-0010
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "podsecuritypolicy"
    not input.spec.requiredDropCapabilities
}

k8s_issue["rulepass"] {
    lower(input.kind) == "podsecuritypolicy"
    rdc := input.spec.requiredDropCapabilities
    count([c | rdc[_] == "NET_RAW"; c := 1]) == 0
    count([c | rdc[_] == "ALL"; c := 1]) == 0
}

rulepass {
    lower(input.kind) == "podsecuritypolicy"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0010: Minimize the admission of containers with the NET_RAW capability (PSP)" {
    k8s_issue["rulepass"]
}

k8s_issue_metadata := {
    "Policy Code": "PR-K8S-0010",
    "Type": "Cloud",
    "Product": "Kubernetes",
    "Language": "Cloud",
    "Policy Title": "Minimize the admission of containers with the NET_RAW capability (PSP) ",
    "Policy Description": "Minimize the admission of containers with the NET_RAW capability (PSP) ",
    "Resource Type": "podsecuritypolicy",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
