#
# PR-AZR-0100
#

package rule
default rulepass = false

# Web application firewall is set to OFF in Security Center
# If Web application firewall is set to ON in Security Center test will pass
# web ports should be restricted on network Security Groups associated to your VM

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass {
    lower(input.type) == "microsoft.authorization/policyassignments"
    contains(input.id, "webApplicationFirewallMonitoring")
}

metadata := {
    "Policy Code": "PR-AZR-0100",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Web application firewall is set to OFF in Security Center",
    "Policy Description": "Turning on Web application firewall will identify if WAF is recommended for the public facing IP instances in your environment. Web Application Firewall or WAF is recommended for any public facing IP instance (VM or Load Balancer) which has an associated Network Security Group with open inbound ports 80 and 443.",
    "Resource Type": "microsoft.authorization/policyassignments",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0"
}
