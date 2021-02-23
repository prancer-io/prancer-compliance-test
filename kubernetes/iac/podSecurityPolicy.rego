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

#
# PR-K8S-0011-DCL
#

default host_ipc = null

k8s_issue["host_ipc"] {
    lower(input.kind) == "podsecuritypolicy"
    input.spec.hostIPC == true
}

host_ipc {
    lower(input.kind) == "podsecuritypolicy"
    not k8s_issue["host_ipc"]
}

host_ipc = false {
    k8s_issue["host_ipc"]
}

host_ipc_err = "PR-K8S-0011-DCL: Minimize the admission of containers wishing to share the host IPC namespace (PSP)" {
    k8s_issue["host_ipc"]
}

#
# PR-K8S-0012-DCL
#

default host_network = null

k8s_issue["host_network"] {
    lower(input.kind) == "podsecuritypolicy"
    input.spec.hostNetwork == true
}

host_network {
    lower(input.kind) == "podsecuritypolicy"
    not k8s_issue["host_network"]
}

host_network = false {
    k8s_issue["host_network"]
}

host_network_err = "PR-K8S-0012-DCL: Minimize the admission of containers wishing to share the host network namespace (PSP)" {
    k8s_issue["host_network"]
}

#
# PR-K8S-0013-DCL
#

default host_pid = null

k8s_issue["host_pid"] {
    lower(input.kind) == "podsecuritypolicy"
    input.spec.hostPID == true
}

host_pid {
    lower(input.kind) == "podsecuritypolicy"
    not k8s_issue["host_pid"]
}

host_pid = false {
    k8s_issue["host_pid"]
}

host_pid_err = "PR-K8S-0013-DCL: Minimize the admission of containers wishing to share the host process ID namespace (PSP)" {
    k8s_issue["host_pid"]
}

#
# PR-K8S-0014-DCL
#

default privilege_escalation = null

k8s_issue["privilege_escalation"] {
    lower(input.kind) == "podsecuritypolicy"
    input.spec.hostPID == true
}

privilege_escalation {
    lower(input.kind) == "podsecuritypolicy"
    not k8s_issue["privilege_escalation"]
}

privilege_escalation = false {
    k8s_issue["privilege_escalation"]
}

privilege_escalation_err = "PR-K8S-0014-DCL: Minimize the admission of containers with allowPrivilegeEscalation (PSP)" {
    k8s_issue["privilege_escalation"]
}

