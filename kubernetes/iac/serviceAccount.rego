package rule

#
# PR-K8S-0035-DCL
#

default sa_token = null

k8s_issue["sa_token"] {
    lower(input.kind) == "serviceaccount"
    input.automountServiceAccountToken == true
}

sa_token {
    lower(input.kind) == "serviceaccount"
    not k8s_issue["sa_token"]
}

sa_token = false {
    k8s_issue["sa_token"]
}

sa_token_err = "PR-K8S-0035-DCL: The default namespace should not be used" {
    k8s_issue["sa_token"]
}
