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
# PR-AZR-CLD-IAM-001
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
    resource := input.resources[_]
    lower(resource.type) == "microsoft.authorization/roledefinitions"
    lower(resource.properties.type) == "customrole"
    azure_issue["custom_roles_dont_have_overly_permission"]
}

custom_roles_dont_have_overly_permission {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.authorization/roledefinitions"
    lower(resource.properties.type) == "customrole"
    not azure_issue["custom_roles_dont_have_overly_permission"]
}

custom_roles_dont_have_overly_permission_err = "Azure custom role definition currently have excessive permissions" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.authorization/roledefinitions"
    lower(resource.properties.type) == "customrole"
    azure_issue["custom_roles_dont_have_overly_permission"]
}

custom_roles_dont_have_overly_permission_metadata := {
    "Policy Code": "PR-AZR-CLD-IAM-001",
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
# PR-AZR-CLD-IAM-002
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
    "Policy Code": "PR-AZR-CLD-IAM-002",
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
# PR-AZR-CLD-IAM-003
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
    "Policy Code": "PR-AZR-CLD-IAM-003",
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
# PR-AZR-CLD-IAM-004
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
    "Policy Code": "PR-AZR-CLD-IAM-004",
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
# PR-AZR-CLD-IAM-005
#

default custom_roles_dont_have_subscription_owner_permission = null

azure_issue["custom_roles_dont_have_subscription_owner_permission"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.authorization/roledefinitions"
    lower(resource.properties.type) == "customrole"
    array_element_contains(resource.properties.assignableScopes, "subscriptions/")
    permissions := resource.properties.permissions[_]
    array_element_startswith(permissions.actions, "*")
}

custom_roles_dont_have_subscription_owner_permission = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.authorization/roledefinitions"
    lower(resource.properties.type) == "customrole"
    azure_issue["custom_roles_dont_have_subscription_owner_permission"]
}

custom_roles_dont_have_subscription_owner_permission {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.authorization/roledefinitions"
    lower(resource.properties.type) == "customrole"
    not azure_issue["custom_roles_dont_have_subscription_owner_permission"]
}

custom_roles_dont_have_subscription_owner_permission_err = "Azure custom role definition currently have subscription owner permission" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.authorization/roledefinitions"
    lower(resource.properties.type) == "customrole"
    azure_issue["custom_roles_dont_have_subscription_owner_permission"]
}

custom_roles_dont_have_subscription_owner_permission_metadata := {
    "Policy Code": "PR-AZR-CLD-IAM-005",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure custom role definition should not have subscription owner permission",
    "Policy Description": "This policy identifies and audit azure subscriptions with custom roles that has subscription owner permission. Least privilege access rule should be followed and only necessary privileges should be assigned instead of allowing full administrative access.",
    "Resource Type": "Microsoft.Authorization/roleDefinitions",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.authorization/roledefinitions?pivots=deployment-language-arm-template"
}


# https://learn.microsoft.com/en-us/azure/templates/microsoft.authorization/roledefinitions?pivots=deployment-language-arm-template
# https://learn.microsoft.com/en-us/rest/api/authorization/role-definitions/list?tabs=HTTP
#
# PR-AZR-CLD-IAM-006
#

default custom_roles_dont_have_wildcard_action = null

azure_issue["custom_roles_dont_have_wildcard_action"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.authorization/roledefinitions"
    lower(resource.properties.type) == "customrole"
    permissions := resource.properties.permissions[_]
    array_element_contains(permissions.actions, "*")
}

custom_roles_dont_have_wildcard_action = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.authorization/roledefinitions"
    lower(resource.properties.type) == "customrole"
    azure_issue["custom_roles_dont_have_wildcard_action"]
}

custom_roles_dont_have_wildcard_action {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.authorization/roledefinitions"
    lower(resource.properties.type) == "customrole"
    not azure_issue["custom_roles_dont_have_wildcard_action"]
}

custom_roles_dont_have_wildcard_action_err = "Azure custom role definition currently have wildcard action" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.authorization/roledefinitions"
    lower(resource.properties.type) == "customrole"
    azure_issue["custom_roles_dont_have_wildcard_action"]
}

custom_roles_dont_have_wildcard_action_metadata := {
    "Policy Code": "PR-AZR-CLD-IAM-006",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure custom role definition should not have wildcard action",
    "Policy Description": "This policy identifies and audit custom roles that has wildcard action. When creating custom roles, you can use the wildcard (*) character to define permissions. It's recommended that you specify Actions and DataActions explicitly instead of using the wildcard (*) character. The additional access and permissions granted through future Actions or DataActions may be unwanted behavior using the wildcard.",
    "Resource Type": "Microsoft.Authorization/roleDefinitions",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.authorization/roledefinitions?pivots=deployment-language-arm-template"
}


# https://learn.microsoft.com/en-us/azure/templates/microsoft.authorization/roleassignments?pivots=deployment-language-arm-template
# https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/list-for-scope?tabs=HTTP
#
# PR-AZR-CLD-IAM-007
#

default role_dont_have_direct_user_assignment = null

azure_issue["role_dont_have_direct_user_assignment"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.authorization/roleassignments"
    lower(resource.properties.principalType) != "group"
}

role_dont_have_direct_user_assignment = false {
    azure_issue["role_dont_have_direct_user_assignment"]
}

role_dont_have_direct_user_assignment {
    not azure_issue["role_dont_have_direct_user_assignment"]
}

role_dont_have_direct_user_assignment_err = "Azure role currently have direct user assignment" {
    azure_issue["role_dont_have_direct_user_assignment"]
}

role_dont_have_direct_user_assignment_metadata := {
    "Policy Code": "PR-AZR-CLD-IAM-007",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure to assign roles to groups, not users",
    "Policy Description": "To make role assignments more manageable, avoid assigning roles directly to users. Instead, assign roles to groups. Assigning roles to groups instead of users also helps minimize the number of role assignments, which has a limit of role assignments per subscription",
    "Resource Type": "Microsoft.Authorization/roleAssignments",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.authorization/roleassignments?pivots=deployment-language-arm-template"
}


# https://learn.microsoft.com/en-us/graph/api/identitysecuritydefaultsenforcementpolicy-get?view=graph-rest-1.0&tabs=http
#
# PR-AZR-CLD-IAM-008
#

default aad_has_security_default_enabled = null

azure_attribute_absence["aad_has_security_default_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.graph.identitysecuritydefaultsenforcementpolicy"
    not has_property(resource.properties, "isEnabled")
}

azure_issue["aad_has_security_default_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.graph.identitysecuritydefaultsenforcementpolicy"
    resource.properties.isEnabled != true
}

aad_has_security_default_enabled {
    lower(input.resources[_].type) == "microsoft.graph.identitysecuritydefaultsenforcementpolicy"
    not azure_attribute_absence["aad_has_security_default_enabled"]
    not azure_issue["aad_has_security_default_enabled"]
}

aad_has_security_default_enabled = false {
    azure_attribute_absence["aad_has_security_default_enabled"]
}

aad_has_security_default_enabled = false {
    azure_issue["aad_has_security_default_enabled"]
}

aad_has_security_default_enabled_err = "AAD currently dont have security default enabled" {
    azure_issue["aad_has_security_default_enabled"]
} else = "Resource type identitySecurityDefaultsEnforcementPolicy dont have property 'isEnabled' available. Ensure its available." {
    azure_attribute_absence["aad_has_security_default_enabled"]
}

aad_has_security_default_enabled_metadata := {
    "Policy Code": "PR-AZR-CLD-IAM-008",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "AAD should have security default enabled",
    "Policy Description": "Security defaults is a set of basic identity security mechanisms recommended by Microsoft. When enabled, these recommendations will be automatically enforced in your organization. Administrators and users will be better protected from common identity related attacks.",
    "Resource Type": "microsoft.graph.identitySecurityDefaultsEnforcementPolicy",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/graph/api/identitysecuritydefaultsenforcementpolicy-get?view=graph-rest-1.0&tabs=http"
}


# https://learn.microsoft.com/en-us/graph/api/authorizationpolicy-get?view=graph-rest-1.0&tabs=http
#
# PR-AZR-CLD-IAM-009
#

default allowed_to_create_app_is_disabled_for_aad_non_admin_users = null

azure_attribute_absence["allowed_to_create_app_is_disabled_for_aad_non_admin_users"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.graph.authorizationpolicy"
    not resource.properties.defaultUserRolePermissions
}

azure_attribute_absence["allowed_to_create_app_is_disabled_for_aad_non_admin_users"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.graph.authorizationpolicy"
    not has_property(resource.properties.defaultUserRolePermissions, "allowedToCreateApps")
}

azure_issue["allowed_to_create_app_is_disabled_for_aad_non_admin_users"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.graph.authorizationpolicy"
    resource.properties.defaultUserRolePermissions.allowedToCreateApps == true
}

allowed_to_create_app_is_disabled_for_aad_non_admin_users {
    lower(input.resources[_].type) == "microsoft.graph.authorizationpolicy"
    not azure_attribute_absence["allowed_to_create_app_is_disabled_for_aad_non_admin_users"]
    not azure_issue["allowed_to_create_app_is_disabled_for_aad_non_admin_users"]
}

allowed_to_create_app_is_disabled_for_aad_non_admin_users = false {
    azure_attribute_absence["allowed_to_create_app_is_disabled_for_aad_non_admin_users"]
}

allowed_to_create_app_is_disabled_for_aad_non_admin_users = false {
    azure_issue["allowed_to_create_app_is_disabled_for_aad_non_admin_users"]
}

allowed_to_create_app_is_disabled_for_aad_non_admin_users_err = "AAD non admin users currently have permission to create apps" {
    azure_issue["allowed_to_create_app_is_disabled_for_aad_non_admin_users"]
} else = "Resource type authorizationPolicy dont have property 'defaultUserRolePermissions.allowedToCreateApps' available. Ensure its available." {
    azure_attribute_absence["allowed_to_create_app_is_disabled_for_aad_non_admin_users"]
}

allowed_to_create_app_is_disabled_for_aad_non_admin_users_metadata := {
    "Policy Code": "PR-AZR-CLD-IAM-009",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "AAD non admin users should not have permission to create apps",
    "Policy Description": "As a good practice only administrators or appropriately delegated users should be able to register applications. This policy will identify AAD non admin users who has app creation permission.",
    "Resource Type": "microsoft.graph.authorizationPolicy",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/graph/api/authorizationpolicy-get?view=graph-rest-1.0&tabs=http"
}


# https://learn.microsoft.com/en-us/graph/api/authorizationpolicy-get?view=graph-rest-1.0&tabs=http
#
# PR-AZR-CLD-IAM-010
#

default only_aad_admin_users_can_invite_guest_users = null

azure_attribute_absence["only_aad_admin_users_can_invite_guest_users"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.graph.authorizationpolicy"
    not resource.properties.allowInvitesFrom
}

azure_issue["only_aad_admin_users_can_invite_guest_users"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.graph.authorizationpolicy"
    lower(resource.properties.allowInvitesFrom) != "adminsandguestinviters"
}

only_aad_admin_users_can_invite_guest_users {
    lower(input.resources[_].type) == "microsoft.graph.authorizationpolicy"
    not azure_attribute_absence["only_aad_admin_users_can_invite_guest_users"]
    not azure_issue["only_aad_admin_users_can_invite_guest_users"]
}

only_aad_admin_users_can_invite_guest_users = false {
    azure_attribute_absence["only_aad_admin_users_can_invite_guest_users"]
}

only_aad_admin_users_can_invite_guest_users = false {
    azure_issue["only_aad_admin_users_can_invite_guest_users"]
}

only_aad_admin_users_can_invite_guest_users_err = "AAD non admin users currently have permission to invite guest users" {
    azure_issue["only_aad_admin_users_can_invite_guest_users"]
} else = "Resource type authorizationPolicy dont have property 'allowInvitesFrom' available. Ensure its available." {
    azure_attribute_absence["only_aad_admin_users_can_invite_guest_users"]
}

only_aad_admin_users_can_invite_guest_users_metadata := {
    "Policy Code": "PR-AZR-CLD-IAM-010",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure only AAD users assigned to specific admin roles can invite guest users",
    "Policy Description": "Restrict invitations to users with specific administrative roles only.",
    "Resource Type": "microsoft.graph.authorizationPolicy",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/graph/api/authorizationpolicy-get?view=graph-rest-1.0&tabs=http"
}


# https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-beta&tabs=http
#
# PR-AZR-CLD-IAM-011
#

default aad_users_has_mfa_enabled = null

azure_attribute_absence["aad_users_has_mfa_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.graph.userregistrationdetails"
    not has_property(resource.properties, "isMfaRegistered")
}

azure_issue["aad_users_has_mfa_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.graph.userregistrationdetails"
    resource.properties.isMfaRegistered != true
}

aad_users_has_mfa_enabled {
    lower(input.resources[_].type) == "microsoft.graph.userregistrationdetails"
    not azure_attribute_absence["aad_users_has_mfa_enabled"]
    not azure_issue["aad_users_has_mfa_enabled"]
}

aad_users_has_mfa_enabled = false {
    azure_attribute_absence["aad_users_has_mfa_enabled"]
}

aad_users_has_mfa_enabled = false {
    azure_issue["aad_users_has_mfa_enabled"]
}

aad_users_has_mfa_enabled_err = "AAD users currently dont have MFA enabled" {
    azure_issue["aad_users_has_mfa_enabled"]
} else = "Resource type userRegistrationDetails dont have property 'isMfaRegistered' available. Ensure its available." {
    azure_attribute_absence["aad_users_has_mfa_enabled"]
}

aad_users_has_mfa_enabled_metadata := {
    "Policy Code": "PR-AZR-CLD-IAM-011",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "AAD users should have MFA enabled",
    "Policy Description": "This policy identifies Azure users for whom AD MFA (Active Directory Multi-Factor Authentication) is not enabled. Azure AD MFA is a simple best practice that adds an extra layer of protection on top of your user name and password. MFA provides increased security for your Azure account settings and resources. Enabling Azure AD Multi-Factor Authentication using Conditional Access policies is the recommended approach to protect users.",
    "Resource Type": "microsoft.graph.userRegistrationDetails",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-beta&tabs=http"
}


# https://learn.microsoft.com/en-us/graph/api/authorizationpolicy-get?view=graph-rest-1.0&tabs=http
#
# PR-AZR-CLD-IAM-012
#

default allowed_to_create_security_group_is_disabled_for_aad_non_admin_users = null

azure_attribute_absence["allowed_to_create_security_group_is_disabled_for_aad_non_admin_users"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.graph.authorizationpolicy"
    not resource.properties.defaultUserRolePermissions
}

azure_attribute_absence["allowed_to_create_security_group_is_disabled_for_aad_non_admin_users"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.graph.authorizationpolicy"
    not has_property(resource.properties.defaultUserRolePermissions, "allowedToCreateSecurityGroups")
}

azure_issue["allowed_to_create_security_group_is_disabled_for_aad_non_admin_users"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.graph.authorizationpolicy"
    resource.properties.defaultUserRolePermissions.allowedToCreateSecurityGroups == true
}

allowed_to_create_security_group_is_disabled_for_aad_non_admin_users {
    lower(input.resources[_].type) == "microsoft.graph.authorizationpolicy"
    not azure_attribute_absence["allowed_to_create_security_group_is_disabled_for_aad_non_admin_users"]
    not azure_issue["allowed_to_create_security_group_is_disabled_for_aad_non_admin_users"]
}

allowed_to_create_security_group_is_disabled_for_aad_non_admin_users = false {
    azure_attribute_absence["allowed_to_create_security_group_is_disabled_for_aad_non_admin_users"]
}

allowed_to_create_security_group_is_disabled_for_aad_non_admin_users = false {
    azure_issue["allowed_to_create_security_group_is_disabled_for_aad_non_admin_users"]
}

allowed_to_create_security_group_is_disabled_for_aad_non_admin_users_err = "AAD non admin users currently have permission to create security groups" {
    azure_issue["allowed_to_create_security_group_is_disabled_for_aad_non_admin_users"]
} else = "Resource type authorizationPolicy dont have property 'defaultUserRolePermissions.allowedToCreateSecurityGroups' available. Ensure its available." {
    azure_attribute_absence["allowed_to_create_security_group_is_disabled_for_aad_non_admin_users"]
}

allowed_to_create_security_group_is_disabled_for_aad_non_admin_users_metadata := {
    "Policy Code": "PR-AZR-CLD-IAM-012",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "AAD non admin users should not have permission to create security groups",
    "Policy Description": "As a good practice only administrators should be able to create security groups. This policy will identify AAD non admin users who has security group creation permission",
    "Resource Type": "microsoft.graph.authorizationPolicy",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/graph/api/authorizationpolicy-get?view=graph-rest-1.0&tabs=http"
}


# https://learn.microsoft.com/en-us/graph/api/authorizationpolicy-get?view=graph-rest-1.0&tabs=http
#
# PR-AZR-CLD-IAM-013
#

default aad_users_can_consent_to_apps_accessing_company_data_on_their_behalf_is_disabled = null

azure_attribute_absence["aad_users_can_consent_to_apps_accessing_company_data_on_their_behalf_is_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.graph.authorizationpolicy"
    not resource.properties.defaultUserRolePermissions
}

azure_attribute_absence["aad_users_can_consent_to_apps_accessing_company_data_on_their_behalf_is_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.graph.authorizationpolicy"
    not has_property(resource.properties.defaultUserRolePermissions, "permissionGrantPoliciesAssigned")
}

azure_issue["aad_users_can_consent_to_apps_accessing_company_data_on_their_behalf_is_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.graph.authorizationpolicy"
    not array_contains(resource.properties.defaultUserRolePermissions.permissionGrantPoliciesAssigned, "microsoft-user-default-legacy")
}

aad_users_can_consent_to_apps_accessing_company_data_on_their_behalf_is_disabled {
    lower(input.resources[_].type) == "microsoft.graph.authorizationpolicy"
    not azure_attribute_absence["aad_users_can_consent_to_apps_accessing_company_data_on_their_behalf_is_disabled"]
    not azure_issue["aad_users_can_consent_to_apps_accessing_company_data_on_their_behalf_is_disabled"]
}

aad_users_can_consent_to_apps_accessing_company_data_on_their_behalf_is_disabled = false {
    azure_attribute_absence["aad_users_can_consent_to_apps_accessing_company_data_on_their_behalf_is_disabled"]
}

aad_users_can_consent_to_apps_accessing_company_data_on_their_behalf_is_disabled = false {
    azure_issue["aad_users_can_consent_to_apps_accessing_company_data_on_their_behalf_is_disabled"]
}

aad_users_can_consent_to_apps_accessing_company_data_on_their_behalf_is_disabled_err = "'Users can consent to apps accessing company data on their behalf' configuration is currently not disabled" {
    azure_issue["aad_users_can_consent_to_apps_accessing_company_data_on_their_behalf_is_disabled"]
} else = "Resource type authorizationPolicy dont have property 'defaultUserRolePermissions.permissionGrantPoliciesAssigned' available. Ensure its available." {
    azure_attribute_absence["aad_users_can_consent_to_apps_accessing_company_data_on_their_behalf_is_disabled"]
}

aad_users_can_consent_to_apps_accessing_company_data_on_their_behalf_is_disabled_metadata := {
    "Policy Code": "PR-AZR-CLD-IAM-013",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure 'Users can consent to apps accessing company data on their behalf' configuration is disabled",
    "Policy Description": "This policy identifies Azure Active Directory which have 'Users can consent to apps accessing company data on their behalf' configuration enabled. User profiles contain private information which could be shared with others without requiring any further consent from the user if this configuration is enabled. It is recommended not to allow users to use their identity outside of the cloud environment.",
    "Resource Type": "microsoft.graph.authorizationPolicy",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/graph/api/authorizationpolicy-get?view=graph-rest-1.0&tabs=http"
}


# https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-beta&tabs=http
#
# PR-AZR-CLD-IAM-014
#

default aad_dont_have_any_guest_users = null

azure_attribute_absence["aad_dont_have_any_guest_users"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.graph.userregistrationdetails"
    not resource.properties.userType
}

azure_issue["aad_dont_have_any_guest_users"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.graph.userregistrationdetails"
    lower(resource.properties.userType) == "guest"
}

aad_dont_have_any_guest_users {
    lower(input.resources[_].type) == "microsoft.graph.userregistrationdetails"
    not azure_attribute_absence["aad_dont_have_any_guest_users"]
    not azure_issue["aad_dont_have_any_guest_users"]
}

aad_dont_have_any_guest_users = false {
    azure_attribute_absence["aad_dont_have_any_guest_users"]
}

aad_dont_have_any_guest_users = false {
    azure_issue["aad_dont_have_any_guest_users"]
}

aad_dont_have_any_guest_users_err = "AAD currently have guest users" {
    azure_issue["aad_dont_have_any_guest_users"]
} else = "Resource type userRegistrationDetails dont have property 'userType' available. Ensure its available." {
    azure_attribute_absence["aad_dont_have_any_guest_users"]
}

aad_dont_have_any_guest_users_metadata := {
    "Policy Code": "PR-AZR-CLD-IAM-014",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure AAD dont have guest users",
    "Policy Description": "This policy identifies Azure Active Directory Guest users. Azure Active Directory allows B2B collaboration which lets you invite people from outside your organisation to be guest users in your cloud account. Avoid creating guest user in your cloud account unless you have business need. Guest users are usually added for users outside your employee on-boarding/off-boarding process and could potentially be overlooked leading to a potential vulnerability.",
    "Resource Type": "microsoft.graph.userRegistrationDetails",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-beta&tabs=http"
}
