package rule

#
# PR-K8S-0008-DCL
#

default privileged = null

k8s_issue["privileged"] {
    lower(input.kind) == "podsecuritypolicy"
    input.spec.privileged
}

privileged {
    lower(input.kind) == "podsecuritypolicy"
    not k8s_issue["privileged"]
}

privileged = false {
    k8s_issue["privileged"]
}

privileged_err = "PR-K8S-0008-DCL: Minimize the admission of privileged containers (PSP)" {
    k8s_issue["privileged"]
}

#
# PR-K8S-0009-DCL
#

default run_as_root = null

k8s_issue["run_as_root"] {
    lower(input.kind) == "podsecuritypolicy"
    lower(input.spec.runAsUser.rule) == "runasany"
}

k8s_issue["run_as_root"] {
    lower(input.kind) == "podsecuritypolicy"
    lower(input.spec.runAsUser.rule) == "mustrunas"
    input.spec.runAsUser.ranges[_].min == 0
}

run_as_root {
    lower(input.kind) == "podsecuritypolicy"
    not k8s_issue["run_as_root"]
}

run_as_root = false {
    k8s_issue["run_as_root"]
}

run_as_root_err = "PR-K8S-0009-DCL: Minimize the admission of root containers (PSP)" {
    k8s_issue["run_as_root"]
}

#
# PR-K8S-0010-DCL
#

default drop_capabilities = null

k8s_issue["drop_capabilities"] {
    lower(input.kind) == "podsecuritypolicy"
    not input.spec.requiredDropCapabilities
}

k8s_issue["drop_capabilities"] {
    lower(input.kind) == "podsecuritypolicy"
    rdc := input.spec.requiredDropCapabilities
    count([c | rdc[_] == "NET_RAW"; c := 1]) == 0
    count([c | rdc[_] == "ALL"; c := 1]) == 0
}

drop_capabilities {
    lower(input.kind) == "podsecuritypolicy"
    not k8s_issue["drop_capabilities"]
}

drop_capabilities = false {
    k8s_issue["drop_capabilities"]
}

drop_capabilities_err = "PR-K8S-0010-DCL: Minimize the admission of containers with the NET_RAW capability (PSP)" {
    k8s_issue["drop_capabilities"]
}
