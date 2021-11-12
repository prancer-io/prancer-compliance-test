package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_definition

# PR-AZR-TRF-ARD-001

default no_custom_subs_owner_role_created = null

contains(array, element) = true {
  lower(array[_]) == element
} else = false { true }

azure_attribute_absence["no_custom_subs_owner_role_created"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_role_definition"
    not resource.properties.permissions
}

azure_attribute_absence["no_custom_subs_owner_role_created"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_role_definition"
    permissions := resource.properties.permissions[_]
    not permissions.actions
}

azure_issue["no_custom_subs_owner_role_created"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_role_definition"
    permissions := resource.properties.permissions[_]
    contains(permissions.actions, "*")
}

no_custom_subs_owner_role_created {
    lower(input.resources[_].type) == "azurerm_role_definition"
    azure_attribute_absence["no_custom_subs_owner_role_created"]
    not azure_issue["no_custom_subs_owner_role_created"]
}

no_custom_subs_owner_role_created {
    lower(input.resources[_].type) == "azurerm_role_definition"
    not azure_attribute_absence["no_custom_subs_owner_role_created"]
    not azure_issue["no_custom_subs_owner_role_created"]
}

no_custom_subs_owner_role_created = false {
    azure_issue["no_custom_subs_owner_role_created"]
}

no_custom_subs_owner_role_created_err = "Custom Role Definition currently has permission action entry to create subscription owner role which could be a security issue." {
    azure_issue["no_custom_subs_owner_role_created"]
}

no_custom_subs_owner_role_created_metadata := {
    "Policy Code": "PR-AZR-TRF-ARD-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Custom Role Definition should not create subscription owner role",
    "Policy Description": "Manages a custom Role Definition, used to assign Roles to Users/Principals. This policy will identify custom role definition which has action permission set to subscription owner and alert if exist.",
    "Resource Type": "azurerm_role_definition",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_definition"
}