package rule

#
# PR-K8S-0009
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "podsecuritypolicy"
    lower(input.spec.runAsUser.rule) == "runasany"
}

k8s_issue["rulepass"] {
    lower(input.kind) == "podsecuritypolicy"
    lower(input.spec.runAsUser.rule) == "mustrunas"
    input.spec.runAsUser.ranges[_].min == 0
}

rulepass {
    lower(input.kind) == "podsecuritypolicy"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0009: Minimize the admission of root containers (PSP)" {
    k8s_issue["rulepass"]
}
