package rule

#
# PR-K8S-0021
#

default rulepass = null

k8s_issue["rulepass"] {
    count([
        c | regex.match("seccomp.security.alpha.kubernetes.io\/pod.*", input.metadata.annotations[_]);
        c := 1]) == 0
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0021: Ensure that the seccomp profile is set to runtime/default in your pod definitions" {
    k8s_issue["rulepass"]
}
