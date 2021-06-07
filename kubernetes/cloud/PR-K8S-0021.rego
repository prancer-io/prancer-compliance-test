package rule

#
# PR-K8S-0021
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "pod"
    count([
        c | regex.match("seccomp.security.alpha.kubernetes.io\/pod.*", input.metadata.annotations[_]);
        c := 1]) == 0
}

rulepass {
    lower(input.kind) == "pod"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0021: Ensure that the seccomp profile is set to runtime/default in your pod definitions" {
    k8s_issue["rulepass"]
}

k8s_issue_metadata := {
    "Policy Code": "PR-K8S-0021",
    "Type": "Cloud",
    "Product": "Kubernetes",
    "Language": "Cloud",
    "Policy Title": "Ensure that the seccomp profile is set to runtime/default in your pod definitions ",
    "Policy Description": "Ensure that the seccomp profile is set to runtime/default in your pod definitions ",
    "Resource Type": "pod",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
