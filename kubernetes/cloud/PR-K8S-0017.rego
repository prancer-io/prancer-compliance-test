package rule

#
# PR-K8S-0017
#

default rulepass = null

k8s_issue["rulepass"] {
    input.spec.containers[_].name == "etcd"
    input.metadata.namespace == "kube-system"
    input.spec.containers[_].command[_] == "--peer-auto-tls=true"
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0017: Do not use automatically generated self-signed certificates for TLS connections between peers. etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should be accessible only by authenticated etcd peers in the etcd cluster. Hence, do not use self-signed certificates for authentication." {
    k8s_issue["rulepass"]
}
