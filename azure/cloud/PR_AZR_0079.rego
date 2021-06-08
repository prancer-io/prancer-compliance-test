#
# PR-AZR-0079
#

package rule
default rulepass = false

# Next generation firewall is set to OFF in Security Center
# If Next generation firewall is set to ON in Security Center test will pass
# access through internet facing endpoint should be restricted

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass {
    lower(input.type) == "microsoft.authorization/policyassignments"
    contains(input.id, "nextGenerationFirewallMonitoring")
}

metadata := {
    "Policy Code": "PR-AZR-0079",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Next generation firewall is set to OFF in Security Center",
    "Policy Description": "Turning on Next Generation Firewall (NGFW) will extend protection beyond a traditional firewall setting of Network Security Groups in Microsoft Azure environment. A Next-Generation Firewall (NGFW) is a part of the third generation of firewall technology, combining a traditional firewall with other network device filtering functionalities.",
    "Compliance": ["CIS","CSA-CCM","ISO 27001","NIST 800","PCI-DSS"],
    "Resource Type": "microsoft.authorization/policyassignments",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0"
}
