package rule

#
# PR-K8S-0019
#

default rulepass = null

k8s_issue["rulepass"] {
    input.spec.containers[_].name == "kube-apiserver"
    input.metadata.namespace == "kube-system"
    regex.match("--enable-admission-plugins.*AlwaysAdmit.*", input.spec.containers[_].command[_])
}

k8s_issue["rulepass"] {
    input.spec.containers[_].name == "kube-apiserver"
    input.metadata.namespace == "kube-system"
    count([c | contains(input.spec.containers[_].command[_], "enable-admission-plugins"); c := 1]) == 0
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0019: Do not allow all requests. Setting admission control plugin AlwaysAdmit allows all requests and do not filter any requests." {
    k8s_issue["rulepass"]
}
