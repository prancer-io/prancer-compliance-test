#
# PR-AZR-0090
#

package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/2017-04-01/activitylogalerts

rulepass {
    lower(input.type) == "microsoft.insights/activitylogalerts"
    input.properties.enabled == true
}

metadata := {
    "Policy Code": "PR-AZR-0090",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Send me emails about alerts is set to OFF in Security Center",
    "Policy Description": "Turning on Send me emails about alerts will enable Microsoft to send you emails about any high severity alerts in your environment. This will make sure that you are aware of any security issues and take prompt actions to mitigate the risks.",
    "Compliance": ["CIS","CSA-CCM","HIPAA","ISO 27001","NIST 800","PCI-DSS"],
    "Resource Type": "microsoft.insights/activitylogalerts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/2017-04-01/activitylogalerts"
}
