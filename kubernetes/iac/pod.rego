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

#
# PR-K8S-0018-DCL
#

default run_privileged_pod = null

k8s_issue["run_privileged_pod"] {
    lower(input.kind) == "daemonset"
    input.spec.template.spec.containers[_].securityContext.privileged == true
}

k8s_issue["run_privileged_pod"] {
    lower(input.kind) == "deployment"
    input.spec.template.spec.containers[_].securityContext.privileged == true
}

k8s_issue["run_privileged_pod"] {
    lower(input.kind) == "statefulset"
    input.spec.template.spec.containers[_].securityContext.privileged == true
}

run_privileged_pod {
    lower(input.kind) == "daemonset"
    not k8s_issue["run_privileged_pod"]
}

run_privileged_pod {
    lower(input.kind) == "deployment"
    not k8s_issue["run_privileged_pod"]
}

run_privileged_pod {
    lower(input.kind) == "statefulset"
    not k8s_issue["run_privileged_pod"]
}

run_privileged_pod = false {
    k8s_issue["run_privileged_pod"]
}

run_privileged_pod_err = "PR-K8S-0018-DCL: Ensure that Containers are not running in privileged mode" {
    k8s_issue["run_privileged_pod"]
}

#
# PR-K8S-0030-DCL
#

default pod_default_ns = null

k8s_issue["pod_default_ns"] {
    lower(input.kind) == "daemonset"
    input.namespace == "default"
}

k8s_issue["pod_default_ns"] {
    lower(input.kind) == "deployment"
    input.namespace == "default"
}

k8s_issue["pod_default_ns"] {
    lower(input.kind) == "statefulset"
    input.namespace == "default"
}

pod_default_ns {
    lower(input.kind) == "daemonset"
    not k8s_issue["pod_default_ns"]
}

pod_default_ns {
    lower(input.kind) == "deployment"
    not k8s_issue["pod_default_ns"]
}

pod_default_ns {
    lower(input.kind) == "statefulset"
    not k8s_issue["pod_default_ns"]
}

pod_default_ns = false {
    k8s_issue["pod_default_ns"]
}

pod_default_ns_err = "PR-K8S-0018-DCL: The default namespace should not be used" {
    k8s_issue["pod_default_ns"]
}
