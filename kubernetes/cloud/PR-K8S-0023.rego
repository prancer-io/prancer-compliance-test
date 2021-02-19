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

rulepass_err = "PR-K8S-0023: Containers with no AppArmor profile - AppArmor is a Linux kernel security module that supplements the standard Linux user and group based permissions to confine programs to a limited set of resources. AppArmor can be configured for any application to reduce its potential attack surface and provide greater in-depth defense. It is configured through profiles tuned to whitelist the access needed by a specific program or container, such as Linux capabilities, network access, file permissions, etc. Each profile can be run in either enforcing mode, which blocks access to disallowed resources, or complain mode, which only reports violations." {
    k8s_issue["rulepass"]
}
