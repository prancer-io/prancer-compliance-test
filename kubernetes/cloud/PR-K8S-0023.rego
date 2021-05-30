package rule

#
# PR-K8S-0023
#

default rulepass = null

k8s_issue["rulepass"] {
    lower(input.kind) == "pod"
    count([
        c | regex.match(
        	"container.apparmor.security.beta.kubernetes.io\/pod.*", 
        	input.metadata.annotations[_]
        );
        c := 1]) == 0
}

rulepass {
    lower(input.kind) == "pod"
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0023: Ensure containers are secured with AppArmor profile" {
    k8s_issue["rulepass"]
}

k8s_issue_metadata := {
    "Policy Code": "PR-K8S-0023",
    "Type": "Cloud",
    "Product": "Kubernetes",
    "Language": "Cloud",
    "Policy Title": "Ensure containers are secured with AppArmor profile ",
    "Policy Description": "Ensure containers are secured with AppArmor profile ",
    "Resource Type": "pod",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
