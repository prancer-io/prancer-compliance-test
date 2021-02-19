package rule

#
# PR-K8S-0026
#

default rulepass = null

k8s_issue["rulepass"] {
    input.spec.containers[_].name == "kube-apiserver"
    input.metadata.namespace == "kube-system"
    count([
        c | regex.match("--enable-admission-plugins=.*PodSecurityPolicy.*", input.spec.containers[_].command[_]);
        c := 1]) == 0
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0026: Reject creating pods that do not match Pod Security Policies. A Pod Security Policy is a cluster-level resource that controls the actions that a pod can perform and what it has the ability to access. The PodSecurityPolicy objects define a set of conditions that a pod must run with in order to be accepted into the system. Pod Security Policies are comprised of settings and strategies that control the security features a pod has access to and hence this must be used to control pod access permissions." {
    k8s_issue["rulepass"]
}
