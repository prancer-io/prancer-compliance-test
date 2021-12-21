package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.authorization/2016-09-01/locks

#
# PR-AZR-CLD-AML-008
#

default rg_locks = null

# azure_attribute_absence["rg_locks"] {
#     count([c | lower(input.resources[_].type) == "microsoft.resources/resourcegroups"; c := 1]) != count([c | lower(input.resources[_].type) == "microsoft.authorization/locks"; c := 1])
# }

azure_attribute_absence["rg_locks"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.authorization/locks"
    not resource.properties.scope
}


azure_attribute_absence["rg_locks"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.authorization/locks"
    not resource.properties.level
}


azure_issue["rg_locks"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.authorization/locks"
    contains(lower(resource.properties.scope), "resourcegroups")
    lower(resource.properties.level) != "cannotdelete"
}


rg_locks {
    lower(input.resources[_].type) == "microsoft.resources/resourcegroups"
    not azure_attribute_absence["rg_locks"]
    not azure_issue["rg_locks"]
}

rg_locks = false {
    lower(input.resources[_].type) == "microsoft.resources/resourcegroups"
    azure_issue["rg_locks"]
}

rg_locks = false {
    lower(input.resources[_].type) == "microsoft.resources/resourcegroups"
    azure_attribute_absence["rg_locks"]
}

rg_locks_err = "Azure Deployment Scope Resource Group currently dont have any remove protection resource lock configured" {
    lower(input.resources[_].type) == "microsoft.resources/resourcegroups"
    azure_issue["rg_locks"]
}

rg_locks_miss_err = "Resource lock property 'level' is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.resources/resourcegroups"
    azure_attribute_absence["rg_locks"]
}

rg_locks_metadata := {
    "Policy Code": "PR-AZR-CLD-AML-008",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Deployment Scope Resource Group should have a remove protection resource lock configured",
    "Policy Description": "Azure Resource Manager locks provide a way to lock down Azure resources from being deleted or modified. The lock level can be set to either 'CanNotDelete' or 'ReadOnly'. When you apply a lock at a parent scope, all resources within the scope inherit the same lock, and the most restrictive lock takes precedence.<br><br>This policy identifies Azure Resource Groups that do not have a lock set. As a best practice, place a lock on important resources to prevent accidental or malicious modification or deletion by unauthorized users.",
    "Resource Type": "microsoft.authorization/locks",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.authorization/2016-09-01/locks"
}
