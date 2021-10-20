#
# PR-AZR-0052
#

package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.authorization/2016-09-01/locks

rulepass {
    lower(input.type) == "microsoft.authorization/locks"
    contains(input.id, "resourceGroups")
    input.properties.level == "CanNotDelete"
}

metadata := {
    "Policy Code": "PR-AZR-0052",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure Resource Group does not have a resource lock",
    "Policy Description": "Azure Resource Manager locks provide a way to lock down Azure resources from being deleted or modified. The lock level can be set to either 'CanNotDelete' or 'ReadOnly'. When you apply a lock at a parent scope, all resources within the scope inherit the same lock, and the most restrictive lock takes precedence.</br> </br> This policy identifies Azure Resource Groups that do not have a lock set. As a best practice, place a lock on important resources to prevent accidental or malicious modification or deletion by unauthorized users.",
    "Resource Type": "microsoft.authorization/locks",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.authorization/2016-09-01/locks"
}
