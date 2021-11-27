package rule

#
# PR-K8S-0035-DCL
#

default sa_token = null

k8s_issue["sa_token"] {
    lower(input.kind) == "serviceaccount"
    lower(input.metadata.name) == "default"
    input.automountServiceAccountToken == true
}

source_path[{"sa_token":metadata}] {
    lower(input.kind) == "serviceaccount"
    lower(input.metadata.name) == "default"
    input.automountServiceAccountToken == true
    metadata:= {
        "resource_path": [["automountServiceAccountToken"]]
    }
}

k8s_issue["sa_token"] {
    lower(input.kind) == "serviceaccount"
    lower(input.metadata.name) == "default"
    lower(input.automountServiceAccountToken) == "true"
}

source_path[{"sa_token":metadata}] {
    lower(input.kind) == "serviceaccount"
    lower(input.metadata.name) == "default"
    lower(input.automountServiceAccountToken) == "true"
    metadata:= {
        "resource_path": [["automountServiceAccountToken"]]
    }
}

sa_token {
    lower(input.kind) == "serviceaccount"
    not k8s_issue["sa_token"]
}

sa_token = false {
    k8s_issue["sa_token"]
}

sa_token_err = "PR-K8S-0035-DCL: Ensure That Default Service Accounts Are Not Actively Used" {
    k8s_issue["sa_token"]
}

sa_token_metadata := {
    "Policy Code": "PR-K8S-0035-DCL",
    "Type": "IaC",
    "Product": "Kubernetes",
    "Language": "K8s DL",
    "Policy Title": "Ensure That Default Service Accounts Are Not Actively Used ",
    "Policy Description": "The default service account should not be used to ensure that rights granted to applications can be more easily audited and reviewed.",
    "Resource Type": "serviceaccount",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
