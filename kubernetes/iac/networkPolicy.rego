package rule

#
# PR-K8S-0036-DCL
#

default empty_ingress = null

k8s_issue["empty_ingress"] {
    lower(input.kind) == "networkpolicy"
    not input.spec.ingress
}

k8s_issue["empty_ingress"] {
    lower(input.kind) == "networkpolicy"
    count(input.spec.ingress) == 0
}

empty_ingress {
    lower(input.kind) == "networkpolicy"
    not k8s_issue["empty_ingress"]
}

empty_ingress = false {
    k8s_issue["empty_ingress"]
}

empty_ingress_err = "PR-K8S-0036-DCL: Restrict Traffic Among Pods with a Network Policy" {
    k8s_issue["empty_ingress"]
}
