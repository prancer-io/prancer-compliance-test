package rule

#
# PR-K8S-0071
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "pod"
    input.spec.containers[_].name == "kube-apiserver"
    input.metadata.namespace == "kube-system"
    count([
        c | regex.match("--etcd-certfile=.*", input.spec.containers[_].command[_]);
        c := 1]) == 0
}

k8s_issue["rulepass"] {
    lower(input.kind) == "pod"
    input.spec.containers[_].name == "kube-apiserver"
    input.metadata.namespace == "kube-system"
    count([
        c | regex.match("--etcd-keyfile=.*", input.spec.containers[_].command[_]);
        c := 1]) == 0
}

rulepass {
    lower(input.kind) == "pod"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0071: Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate (API Server)" {
    k8s_issue["rulepass"]
}

k8s_issue_metadata := {
    "Policy Code": "PR-K8S-0071",
    "Type": "Cloud",
    "Product": "Kubernetes",
    "Language": "Cloud",
    "Policy Title": "Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate (API Server) ",
    "Policy Description": "Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate (API Server) ",
    "Resource Type": "pod",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
