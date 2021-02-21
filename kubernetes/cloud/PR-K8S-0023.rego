package rule

#
# PR-K8S-0023
#

default rulepass = null

k8s_issue["rulepass"] {
    count([
        c | regex.match(
        	"container.apparmor.security.beta.kubernetes.io\/pod.*", 
        	input.metadata.annotations[_]
        );
        c := 1]) == 0
}

rulepass {
    not k8s_issue["rulepass"]
}

rulepass = false {
    k8s_issue["rulepass"]
}

rulepass_err = "PR-K8S-0023: Ensure containers are secured with AppArmor profile" {
    k8s_issue["rulepass"]
}
