package rule

#
# PR-K8S-0028
#

default rulepass = null

k8s_issue["rulepass"] {
    input.spec.containers[_].name == "kube-apiserver"
    input.metadata.namespace == "kube-system"
    count([
        c | regex.match("--anonymous-auth=.*true.*", input.spec.containers[_].command[_]);
        c := 1]) > 0
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0028: Disable anonymous requests to the API server.When enabled, requests that are not rejected by other configured authentication methods are treated as anonymous requests. These requests are then served by the API server. You should rely on authentication to authorize access and disallow anonymous requests." {
    k8s_issue["rulepass"]
}
