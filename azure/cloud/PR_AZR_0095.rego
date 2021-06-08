#
# PR-AZR-0095
#

package rule
default rulepass = false

# System updates is set to OFF in Security Center
# If System updates is set to ON in Security Center test will pass
# System updates on virtual machine scale sets should be installed

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass {
    lower(input.type) == "microsoft.authorization/policyassignments"
    contains(input.id, "systemUpdatesMonitoring")
}

metadata := {
    "Policy Code": "PR-AZR-0095",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "System updates is set to OFF in Security Center",
    "Policy Description": "Turning on the System updates will retrieve a list of recommended security and critical updates for the given virtual system from Microsoft Windows Update or Microsoft Windows Server Update. These updates are also shown for Linux systems through distro-provided package management systems. The recommendation is to apply all the latest updates.",
    "Compliance": ["CIS","CSA-CCM","ISO 27001","NIST 800","PCI-DSS"],
    "Resource Type": "microsoft.authorization/policyassignments",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0"
}
