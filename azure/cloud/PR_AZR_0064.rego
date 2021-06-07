#
# PR-AZR-0064
#

package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines/extensions

rulepass {
    lower(input.type) == "microsoft.compute/virtualmachines/extensions"
    input.properties.type == "IaaSAntimalware"
}

metadata := {
    "Policy Code": "PR-AZR-0064",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure Virtual Machine does not have endpoint protection installed",
    "Policy Description": "This policy identifies Azure Virtual Machines (VMs) that do not have endpoint protection installed. Installing endpoint protection systems (like Antimalware for Azure) provides for real-time protection capability that helps identify and remove viruses, spyware, and other malicious software. As a best practice, install endpoint protection on all VMs and computers to help identify and remove viruses, spyware, and other malicious software.",
    "Resource Type": "microsoft.compute/virtualmachines/extensions",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines/extensions"
}
