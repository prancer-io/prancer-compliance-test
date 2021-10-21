package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/management_lock

#
# PR-AZR-0052-TRF
#

default rg_locks = null

azure_attribute_absence["rg_locks"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_management_lock"
    not resource.properties.scope
}

azure_attribute_absence["rg_locks"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_management_lock"
    not resource.properties.lock_level
}

azure_issue["rg_locks"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_management_lock"
    contains(lower(resource.properties.scope), "resourcegroups")
    lower(resource.properties.lock_level) != "cannotdelete"
}

rg_locks {
    lower(input.resources[_].type) == "azurerm_management_lock"
    not azure_attribute_absence["rg_locks"]
    not azure_issue["rg_locks"]
}

rg_locks = false {
    azure_issue["rg_locks"]
}

rg_locks = false {
    azure_attribute_absence["rg_locks"]
}

rg_locks_err = "azurerm_management_lock property 'scope' and 'lock_level' need to be exist. one or both are missing from the resource." {
    azure_attribute_absence["rg_locks"]
} else = "Azure Deployment Scope Resource Group currently dont have any remove protection resource lock configured" {
    azure_issue["rg_locks"]
}

rg_locks_metadata := {
    "Policy Code": "PR-AZR-0052-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Deployment Scope Resource Group should have a remove protection resource lock configured",
    "Policy Description": "Azure Resource Manager locks provide a way to lock down Azure resources from being deleted or modified. The lock level can be set to either 'CanNotDelete' or 'ReadOnly'. When you apply a lock at a parent scope, all resources within the scope inherit the same lock, and the most restrictive lock takes precedence.<br><br>This policy identifies Azure Resource Groups that do not have a lock set. As a best practice, place a lock on important resources to prevent accidental or malicious modification or deletion by unauthorized users.",
    "Resource Type": "azurerm_management_lock",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/management_lock"
}
