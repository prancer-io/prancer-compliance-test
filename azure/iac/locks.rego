package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.authorization/2016-09-01/locks

#
# PR-AZR-0052-ARM
#

default rg_locks = null

azure_attribute_absence["rg_locks"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.authorization/locks"
    not resource.properties.level
}

azure_issue["rg_locks"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.authorization/locks"
    contains(lower(resource.id), "resourcegroups")
    lower(resource.properties.level) != "cannotdelete"
}

rg_locks {
    lower(input.resources[_].type) == "microsoft.authorization/locks"
    not azure_issue["rg_locks"]
    not azure_attribute_absence["rg_locks"]
}

rg_locks = false {
    azure_issue["rg_locks"]
}

rg_locks = false {
    azure_attribute_absence["rg_locks"]
}

rg_locks_err = "Azure Resource Group does not have a resource lock" {
    azure_issue["rg_locks"]
}

rg_locks_err = "Lock attribute level missing in the resource" {
    azure_attribute_absence["rg_locks"]
}

rg_locks_metadata := {
    "Policy Code": "PR-AZR-0052-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Resource Group does not have a resource lock",
    "Policy Description": "Azure Resource Manager locks provide a way to lock down Azure resources from being deleted or modified. The lock level can be set to either 'CanNotDelete' or 'ReadOnly'. When you apply a lock at a parent scope, all resources within the scope inherit the same lock, and the most restrictive lock takes precedence._x005F_x000D_ _x005F_x000D_ This policy identifies Azure Resource Groups that do not have a lock set. As a best practice, place a lock on important resources to prevent accidental or malicious modification or deletion by unauthorized users.",
    "Resource Type": "microsoft.authorization/locks",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.authorization/2016-09-01/locks"
}
