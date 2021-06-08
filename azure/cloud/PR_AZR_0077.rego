#
# PR-AZR-0077
#

package rule
default rulepass = false

# Endpoint protection is set to OFF in Security Center
# If Endpoint protection is set to ON in Security Center

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass {
    lower(input.type) == "microsoft.authorization/policyassignments"
    contains(input.id, "vmssEndpointProtectionMonitoring")
}

metadata := {
    "Policy Code": "PR-AZR-0077",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Endpoint protection is set to OFF in Security Center",
    "Policy Description": "Turning on the Endpoint Protection will make sure that any issues or shortcomings in endpoint protection for all Microsoft Windows virtual machines are identified so that they can, in turn, be removed.",
    "Compliance": ["CIS","CSA-CCM","ISO 27001","NIST 800","PCI-DSS"],
    "Resource Type": "microsoft.authorization/policyassignments",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0"
}
