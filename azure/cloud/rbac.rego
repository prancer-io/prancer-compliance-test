package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }

array_element_contains(target_array, element_string) = true {
  contains(lower(target_array[_]), lower(element_string))
} else = false { true }

array_element_startswith(target_array, element_string) = true {
  startswith(lower(target_array[_]), lower(element_string))
} else = false { true }

# https://learn.microsoft.com/en-us/azure/templates/microsoft.authorization/roledefinitions?pivots=deployment-language-arm-template
# https://learn.microsoft.com/en-us/rest/api/authorization/role-definitions/list?tabs=HTTP
#
# PR-AZR-CLD-RBA-001
#

default custom_roles_dont_have_overly_permission = null

azure_issue["custom_roles_dont_have_overly_permission"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.authorization/roledefinitions"
    lower(resource.properties.type) == "customrole"
    array_element_contains(resource.properties.assignableScopes, "/")
    permissions := resource.properties.permissions[_]
    array_element_startswith(permissions.actions, "*")
}

custom_roles_dont_have_overly_permission = false {
    azure_issue["custom_roles_dont_have_overly_permission"]
}

custom_roles_dont_have_overly_permission {
    not azure_issue["custom_roles_dont_have_overly_permission"]
}

custom_roles_dont_have_overly_permission_err = "Azure custom role definition currently have excessive permissions" {
    azure_issue["custom_roles_dont_have_overly_permission"]
}

custom_roles_dont_have_overly_permission_metadata := {
    "Policy Code": "PR-AZR-CLD-RBA-001",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure custom role definition should not have overly permission",
    "Policy Description": "This policy identifies and audit azure subscriptions with custom roles that has overly permission. Least privilege access rule should be followed and only necessary privileges should be assigned instead of allowing full administrative access.",
    "Resource Type": "Microsoft.Authorization/roleDefinitions",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.authorization/roledefinitions?pivots=deployment-language-arm-template"
}


# https://learn.microsoft.com/en-us/azure/templates/microsoft.authorization/roleassignments?pivots=deployment-language-arm-template
# https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/list-for-scope?tabs=HTTP
#
# PR-AZR-CLD-RBA-002
#

default role_assignments_dont_have_implicit_role_management_permissions = null

azure_issue["role_assignments_dont_have_implicit_role_management_permissions"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.authorization/roleassignments"
    permissions := resource.properties.roleDefinition.properties.permissions[_]
    array_element_contains(permissions.actions, "roleAssignments")
}

azure_issue["role_assignments_dont_have_implicit_role_management_permissions"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.authorization/roleassignments"
    permissions := resource.properties.roleDefinition.properties.permissions[_]
    array_element_contains(permissions.actions, "roleDefinitions")
}

role_assignments_dont_have_implicit_role_management_permissions = false {
    azure_issue["role_assignments_dont_have_implicit_role_management_permissions"]
}

role_assignments_dont_have_implicit_role_management_permissions {
    not azure_issue["role_assignments_dont_have_implicit_role_management_permissions"]
}

role_assignments_dont_have_implicit_role_management_permissions_err = "Azure role assignments currently have implicit role management permissions" {
    azure_issue["role_assignments_dont_have_implicit_role_management_permissions"]
}

role_assignments_dont_have_implicit_role_management_permissions_metadata := {
    "Policy Code": "PR-AZR-CLD-RBA-002",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure role assignments should not have implicit role management permissions",
    "Policy Description": "This policy identifies and audit azure role assignments that have implicit role management permission. Azure role assignments should be defined by the principle of least privilege.",
    "Resource Type": "Microsoft.Authorization/roleAssignments",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.authorization/roleassignments?pivots=deployment-language-arm-template"
}


# https://learn.microsoft.com/en-us/azure/templates/microsoft.authorization/roleassignments?pivots=deployment-language-arm-template
# https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/list-for-scope?tabs=HTTP
#
# PR-AZR-CLD-RBA-003
#

default role_assignments_dont_have_implicit_managed_identity_permissions = null

azure_issue["role_assignments_dont_have_implicit_managed_identity_permissions"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.authorization/roleassignments"
    permissions := resource.properties.roleDefinition.properties.permissions[_]
    array_element_contains(permissions.actions, "ManagedIdentity")
}

role_assignments_dont_have_implicit_managed_identity_permissions = false {
    azure_issue["role_assignments_dont_have_implicit_managed_identity_permissions"]
}

role_assignments_dont_have_implicit_managed_identity_permissions {
    not azure_issue["role_assignments_dont_have_implicit_managed_identity_permissions"]
}

role_assignments_dont_have_implicit_managed_identity_permissions_err = "Azure role assignments currently have implicit managed identity permissions" {
    azure_issue["role_assignments_dont_have_implicit_managed_identity_permissions"]
}

role_assignments_dont_have_implicit_managed_identity_permissions_metadata := {
    "Policy Code": "PR-AZR-CLD-RBA-003",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure role assignments should not have implicit managed identity permissions",
    "Policy Description": "This policy identifies and audit azure role assignments that have implicit managed identity permission. Azure role assignments should be defined by the principle of least privilege.",
    "Resource Type": "Microsoft.Authorization/roleAssignments",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.authorization/roleassignments?pivots=deployment-language-arm-template"
}


# https://learn.microsoft.com/en-us/azure/templates/microsoft.authorization/roleassignments?pivots=deployment-language-arm-template
# https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/list-for-scope?tabs=HTTP
#
# PR-AZR-CLD-RBA-004
#

default role_assignments_dont_have_implicit_owner_permissions = null

azure_issue["role_assignments_dont_have_implicit_owner_permissions"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.authorization/roleassignments"
    contains(lower(resource.properties.roleDefinition.properties.roleName), "owner")
}

role_assignments_dont_have_implicit_owner_permissions = false {
    azure_issue["role_assignments_dont_have_implicit_owner_permissions"]
}

role_assignments_dont_have_implicit_owner_permissions {
    not azure_issue["role_assignments_dont_have_implicit_owner_permissions"]
}

role_assignments_dont_have_implicit_owner_permissions_err = "Azure role assignments currently have implicit owner permissions" {
    azure_issue["role_assignments_dont_have_implicit_owner_permissions"]
}

role_assignments_dont_have_implicit_owner_permissions_metadata := {
    "Policy Code": "PR-AZR-CLD-RBA-004",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure role assignments should not have implicit owner permissions",
    "Policy Description": "This policy identifies and audit azure role assignments that have implicit owner permission. Azure role assignments should be defined by the principle of least privilege.",
    "Resource Type": "Microsoft.Authorization/roleAssignments",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.authorization/roleassignments?pivots=deployment-language-arm-template"
}


# https://learn.microsoft.com/en-us/azure/templates/microsoft.authorization/roledefinitions?pivots=deployment-language-arm-template
# https://learn.microsoft.com/en-us/rest/api/authorization/role-definitions/list?tabs=HTTP
#
# PR-AZR-CLD-RBA-005
#

default custom_roles_dont_have_subscription_owner_permission = null

azure_issue["custom_roles_dont_have_subscription_owner_permission"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.authorization/roledefinitions"
    lower(resource.properties.type) == "customrole"
    array_element_contains(resource.properties.assignableScopes, "subscriptions/")
    permissions := resource.properties.permissions[_]
    array_contains(permissions.actions, "*")
}

custom_roles_dont_have_subscription_owner_permission = false {
    azure_issue["custom_roles_dont_have_subscription_owner_permission"]
}

custom_roles_dont_have_subscription_owner_permission {
    not azure_issue["custom_roles_dont_have_subscription_owner_permission"]
}

custom_roles_dont_have_subscription_owner_permission_err = "Azure custom role definition currently have subscription owner permission" {
    azure_issue["custom_roles_dont_have_subscription_owner_permission"]
}

custom_roles_dont_have_subscription_owner_permission_metadata := {
    "Policy Code": "PR-AZR-CLD-RBA-005",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure custom role definition should not have subscription owner permission",
    "Policy Description": "This policy identifies and audit azure subscriptions with custom roles that has subscription owner permission. Least privilege access rule should be followed and only necessary privileges should be assigned instead of allowing full administrative access.",
    "Resource Type": "Microsoft.Authorization/roleDefinitions",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.authorization/roledefinitions?pivots=deployment-language-arm-template"
}
