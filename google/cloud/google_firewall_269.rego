#
# PR-GCP-0002
#

package rule
default rulepass = false

# Default Firewall rule should not have any rules (except http and https)
# if default firewall rule should have any rules

# API and Response Reference : https://cloud.google.com/compute/docs/reference/rest/v1/firewalls/list

rulepass = true {
    lower(input.type) == "compute.v1.firewall"
    count(firewallRuleName) == 0
}

firewallRuleName[input.id] {
    input.name == "default-allow-ssh"
    input.sourceRanges[_]="0.0.0.0/0"
}

firewallRuleName[input.id] {
    input.name == "default-allow-icmp"
    input.sourceRanges[_]="0.0.0.0/0"
}

firewallRuleName[input.id] {
    input.name == "default-allow-internal"
    input.sourceRanges[_]="0.0.0.0/0"
}

firewallRuleName[input.id] {
    input.name == "default-allow-rdp"
    input.sourceRanges[_]="0.0.0.0/0"
}

metadata := {
    "Policy Code": "PR-GCP-0002",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "Default Firewall rule should not have any rules (except http and https)",
    "Policy Description": "Checks to ensure that the default Firewall rule should not have any (non http, https) rules. The default Firewall rules will apply all instances by default in the absence of specific custom rules with higher priority. It is a safe practice to not have these rules in the default Firewall.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls/list"
}
