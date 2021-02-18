package rule

#
# PR-K8S-0013
#

default host_pid = null

k8s_issue["host_pid"] {
    input.spec.hostPID == true
}

host_pid {
    not k8s_issue["host_pid"]
}

host_pid = false {
    k8s_issue["host_pid"]
}

host_pid_err = "PR-K8S-0013: Minimize the admission of containers wishing to share the host process ID namespace (PSP)" {
    k8s_issue["host_pid"]
}
