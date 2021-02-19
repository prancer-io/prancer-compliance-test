package rule

#
# PR-K8S-0033
#

default rulepass = null

k8s_issue["rulepass"] {
    input.spec.containers[_].name == "kube-controller-manager"
    input.metadata.namespace == "kube-system"
    count([
        c | regex.match("--use-service-account-credentials=.*true.*", input.spec.containers[_].command[_]);
        c := 1]) == 0
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0033: Use individual service account credentials for each controller. The controller manager creates a service account per controller in the kube-system namespace, generates a credential for it, and builds a dedicated API client with that service account credential for each controller loop to use. Setting the --use-service-account-credentials to true runs each control loop within the controller manager using a separate service account credential. When used in combination with RBAC, this ensures that the control loops run with the minimum permissions required to perform their intended tasks." {
    k8s_issue["rulepass"]
}
