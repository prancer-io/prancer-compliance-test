package rule

#
# PR-K8S-0016
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "pod"
    input.spec.containers[_].name == "etcd"
    input.metadata.namespace == "kube-system"
    input.spec.containers[_].command[_] == "--peer-client-cert-auth=false"
}

k8s_issue["rulepass"] {
    lower(input.kind) == "pod"
    input.spec.containers[_].name == "etcd"
    input.metadata.namespace == "kube-system"
    count([c | contains(input.spec.containers[_].command[_], "peer-client-cert-auth"); c := 1]) == 0
}

rulepass {
    lower(input.kind) == "pod"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0016: etcd should be configured for peer authentication. etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should be accessible only by authenticated etcd peers in the etcd cluster." {
    k8s_issue["rulepass"]
}

k8s_issue_metadata := {
    "Policy Code": "PR-K8S-0016",
    "Type": "Cloud",
    "Product": "Kubernetes",
    "Language": "Cloud",
    "Policy Title": "etcd should be configured for peer authentication. etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should be accessible only by authenticated etcd peers in the etcd cluster. ",
    "Policy Description": "etcd should be configured for peer authentication. etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should be accessible only by authenticated etcd peers in the etcd cluster. ",
    "Resource Type": "pod",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
