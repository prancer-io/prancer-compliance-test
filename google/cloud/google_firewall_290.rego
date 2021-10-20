#
# PR-GCP-0020
#

package rule
default rulepass = true

# Firewall rules allow inbound traffic from anywhere with no target tags set
# If Firewall rules not allow inbound traffic from anywhere with no target tags set
# API and Response Reference : https://cloud.google.com/compute/docs/reference/rest/v1/firewalls/list
rulepass = false {
    lower(input.type) == "compute.v1.firewall"
    count(notargettags) > 0
}

# 'direction equals "INGRESS" and targetTags[*] does not exist and disabled equals false
notargettags["NO_TARGET_TAGS"] {
    input.direction="INGRESS"
    input.disabled= false
    not input.targetTags
}
# 'direction equals "INGRESS" and targetServiceAccounts[*] does not exist' and disabled equals false
notargettags["NO_TARGET_TAGSSERVICEACCOUNT"] {
    input.direction= "INGRESS"
    input.disabled= false
    not input.targetServiceAccounts
}

metadata := {
    "Policy Code": "PR-GCP-0020",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP Firewall rules allow inbound traffic from anywhere with no target tags set",
    "Policy Description": "This policy identifies GCP Firewall rules which allow inbound traffic from anywhere with no target filtering. </br> </br> The default target is all instances in the network. The use of target tags or target service accounts allows the rule to apply to select instances. Not using any firewall rule filtering may allow a bad actor to brute force their way into the system and potentially get access to the entire network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls/list"
}
