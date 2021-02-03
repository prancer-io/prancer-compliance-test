package rule

#
# PR-K8S-0015-DCL
#

default run_pod_as_root = null

k8s_issue["run_pod_as_root"] {
    lower(input.kind) == "daemonset"
    input.spec.template.spec.containers[_].securityContext.runAsNonRoot == false
}

k8s_issue["run_pod_as_root"] {
    lower(input.kind) == "daemonset"
    input.spec.template.spec.containers[_].securityContext.runAsUser == 0
}

k8s_issue["run_pod_as_root"] {
    lower(input.kind) == "deployment"
    input.spec.template.spec.containers[_].securityContext.runAsNonRoot == false
}

k8s_issue["run_pod_as_root"] {
    lower(input.kind) == "deployment"
    input.spec.template.spec.containers[_].securityContext.runAsUser == 0
}

k8s_issue["run_pod_as_root"] {
    lower(input.kind) == "statefulset"
    input.spec.template.spec.containers[_].securityContext.runAsNonRoot == false
}

k8s_issue["run_pod_as_root"] {
    lower(input.kind) == "statefulset"
    input.spec.template.spec.containers[_].securityContext.runAsUser == 0
}

run_pod_as_root {
    lower(input.kind) == "daemonset"
    not k8s_issue["run_pod_as_root"]
}

run_pod_as_root {
    lower(input.kind) == "deployment"
    not k8s_issue["run_pod_as_root"]
}

run_pod_as_root {
    lower(input.kind) == "statefulset"
    not k8s_issue["run_pod_as_root"]
}

run_pod_as_root = false {
    k8s_issue["run_pod_as_root"]
}

run_pod_as_root_err = "PR-K8S-0015-DCL: Do not generally permit containers to be run as the root user." {
    k8s_issue["run_pod_as_root"]
}
