package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_registry

# PR-AZR-TRF-ACR-002

default adminUserDisabled = null
# default is false
azure_attribute_absence["adminUserDisabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    not resource.properties.admin_enabled
}

azure_issue["adminUserDisabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    resource.properties.admin_enabled != false
}

adminUserDisabled {
    lower(input.resources[_].type) == "azurerm_container_registry"
    azure_attribute_absence["adminUserDisabled"]
    not azure_issue["adminUserDisabled"]
}

adminUserDisabled {
    lower(input.resources[_].type) == "azurerm_container_registry"
    not azure_attribute_absence["adminUserDisabled"]
    not azure_issue["adminUserDisabled"]
}

adminUserDisabled = false {
    azure_issue["adminUserDisabled"]
}

adminUserDisabled_err = "Azure Container Registry admin user is currently not disabled" {
    azure_issue["adminUserDisabled"]
}

adminUserDisabled_metadata := {
    "Policy Code": "PR-AZR-TRF-ACR-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that admin user is disabled for Container Registry",
    "Policy Description": "The value that indicates whether the admin user is enabled. Each container registry includes an admin user account, which is disabled by default. You can enable the admin user and manage its credentials in the Azure portal, or by using the Azure CLI or other Azure tools. All users authenticating with the admin account appear as a single user with push and pull access to the registry. Changing or disabling this account disables registry access for all users who use its credentials.",
    "Resource Type": "azurerm_container_registry",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_registry"
}


# https://docs.microsoft.com/en-us/rest/api/containerregistry/registries/list
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_registry
#
# PR-AZR-TRF-ACR-003
#

default acr_classic = null

azure_attribute_absence["acr_classic"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    not resource.properties.sku
}

azure_issue["acr_classic"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    lower(resource.properties.sku) == "classic"
}

acr_classic {
    lower(input.resources[_].type) == "azurerm_container_registry"
    not azure_attribute_absence["acr_classic"]
    not azure_issue["acr_classic"]
}

acr_classic = false {
    azure_attribute_absence["acr_classic"]
}

acr_classic = false {
    azure_issue["acr_classic"]
}

acr_classic_err = "azurerm_container_registry property 'sku' need to be exist. Its missing from the resource." {
    azure_attribute_absence["acr_classic"]
} else = "Azure Container Registry currently using the deprecated classic registry." {
    azure_issue["acr_classic"]
}

acr_classic_metadata := {
    "Policy Code": "PR-AZR-TRF-ACR-003",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Container Registry should not use the deprecated classic registry",
    "Policy Description": "This policy identifies an Azure Container Registry (ACR) that is using the classic SKU. The initial release of the Azure Container Registry (ACR) service that was offered as a classic SKU is being deprecated and will be unavailable after April 2019. As a best practice, upgrade your existing classic registry to a managed registry.<br><br>For more information, visit https://docs.microsoft.com/en-us/azure/container-registry/container-registry-upgrade",
    "Resource Type": "azurerm_container_registry",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_registry"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_registry
#
# PR-AZR-TRF-ACR-006
#
# Defaults to true
default acr_public_access_disabled = null

azure_attribute_absence["acr_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    not has_property(resource.properties, "public_network_access_enabled")
}

azure_issue["acr_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    resource.properties.public_network_access_enabled == true
}

acr_public_access_disabled {
    lower(input.resources[_].type) == "azurerm_container_registry"
    not azure_attribute_absence["acr_public_access_disabled"]
    not azure_issue["acr_public_access_disabled"]
}

acr_public_access_disabled = false {
    azure_attribute_absence["acr_public_access_disabled"]
}

acr_public_access_disabled = false {
    azure_issue["acr_public_access_disabled"]
}

acr_public_access_disabled_err = "azurerm_container_registry property 'public_network_access_enabled' need to be exist. Its missing from the resource." {
    azure_attribute_absence["acr_public_access_disabled"]
} else = "Azure Container registries public access to All networks is currently not disabled" {
    azure_issue["acr_public_access_disabled"]
}

acr_public_access_disabled_metadata := {
    "Policy Code": "PR-AZR-TRF-ACR-006",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Azure Container registries public access to All networks is disabled",
    "Policy Description": "This policy identifies Azure Container registries which has Public access to All networks enabled. Azure ACR is used to store Docker container images which might contain sensitive information. It is highly recommended to restrict public access from allow access from Selected networks or make it Private by disabling the Public access.",
    "Resource Type": "azurerm_container_registry",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_registry"
}


#
# PR-AZR-TRF-ACR-007
#
# Defaults to true
default acr_repository_scoped_access_token_disabled = null

azure_attribute_absence ["acr_repository_scoped_access_token_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry_token"
    not has_property(resource.properties, "enabled")
}

azure_issue ["acr_repository_scoped_access_token_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry_token"
    lower(resource.properties.enabled) != false
}

acr_repository_scoped_access_token_disabled {
    lower(input.resources[_].type) == "azurerm_container_registry_token"
    not azure_attribute_absence["acr_repository_scoped_access_token_disabled"]
    not azure_issue["acr_repository_scoped_access_token_disabled"]
}

acr_repository_scoped_access_token_disabled = false {
    azure_attribute_absence["acr_repository_scoped_access_token_disabled"]
}

acr_repository_scoped_access_token_disabled = false {
    azure_issue["acr_repository_scoped_access_token_disabled"]
}

acr_repository_scoped_access_token_disabled_err = "Azure Container registries repository scoped access token is currently not disabled" {
    azure_issue["acr_repository_scoped_access_token_disabled"]
} else = "azurerm_container_registry_token property enabled is missing from the resource" {
    azure_attribute_absence["acr_repository_scoped_access_token_disabled"] 
}

acr_repository_scoped_access_token_disabled_metadata := {
    "Policy Code": "PR-AZR-TRF-ACR-007",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Azure Container registries repository scoped access token is disabled",
    "Policy Description": "Disable repository scoped access tokens for your registry so that repositories are not accessible by tokens. Disabling local authentication methods like admin user, repository scoped access tokens and anonymous pull improves security by ensuring that container registries exclusively require Azure Active Directory identities for authentication. Learn more at: https://aka.ms/acr/authentication.",
    "Resource Type": "azurerm_container_registry_token",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_registry_token"
}


#
# PR-AZR-TRF-ACR-008
#
default acr_has_premium_sku = null

azure_attribute_absence ["acr_has_premium_sku"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    not resource.properties.sku
}

azure_issue ["acr_has_premium_sku"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    lower(resource.properties.sku) != "premium"
}

acr_has_premium_sku {
    lower(input.resources[_].type) == "azurerm_container_registry"
    not azure_attribute_absence["acr_has_premium_sku"]
    not azure_issue["acr_has_premium_sku"]
}

acr_has_premium_sku = false {
    azure_attribute_absence["acr_has_premium_sku"]
}

acr_has_premium_sku = false {
    azure_issue["acr_has_premium_sku"]
}

acr_has_premium_sku_err = "Azure Container registries currently dont have SKUs that support Private Links" {
    azure_issue["acr_has_premium_sku"]
} else = "azurerm_container_registry property sku is missing from the resource" {
    azure_attribute_absence["acr_has_premium_sku"] 
}

acr_has_premium_sku_metadata := {
    "Policy Code": "PR-AZR-TRF-ACR-008",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Container registries should have SKUs that support Private Links",
    "Policy Description": "Azure Private Link lets you connect your virtual network to Azure services without a public IP address at the source or destination. The private link platform handles the connectivity between the consumer and services over the Azure backbone network. By mapping private endpoints to your container registries instead of the entire service, data leakage risks are reduced. Learn more at: https://aka.ms/acr/private-link.",
    "Resource Type": "azurerm_container_registry",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_registry"
}


#
# PR-AZR-TRF-ACR-009
#
# Defaults to false
default acr_anonymous_auth_disabled = null

azure_attribute_absence ["acr_anonymous_auth_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    not resource.properties.anonymous_pull_enabled
}

azure_issue ["acr_anonymous_auth_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    resource.properties.anonymous_pull_enabled == true
}

acr_anonymous_auth_disabled {
    lower(input.resources[_].type) == "azurerm_container_registry"
    not azure_attribute_absence["acr_anonymous_auth_disabled"]
    not azure_issue["acr_anonymous_auth_disabled"]
}

acr_anonymous_auth_disabled {
    lower(input.resources[_].type) == "azurerm_container_registry"
    azure_attribute_absence["acr_anonymous_auth_disabled"]
    not azure_issue["acr_anonymous_auth_disabled"]
}

acr_anonymous_auth_disabled = false {
    azure_issue["acr_anonymous_auth_disabled"]
}

acr_anonymous_auth_disabled_err = "Azure Container registries anonymous authentication is currently not disabled" {
    azure_issue["acr_anonymous_auth_disabled"]
}

acr_anonymous_auth_disabled_metadata := {
    "Policy Code": "PR-AZR-TRF-ACR-009",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Azure Container registries has anonymous authentication disabled",
    "Policy Description": "Disable anonymous pull for your registry so that data not accessible by unauthenticated user. Disabling local authentication methods like admin user, repository scoped access tokens and anonymous pull improves security by ensuring that container registries exclusively require Azure Active Directory identities for authentication. Learn more at: https://aka.ms/acr/authentication.",
    "Resource Type": "azurerm_container_registry",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_registry"
}


#
# PR-AZR-TRF-ACR-010
#
default acr_not_allowing_unrestricted_network_access = null

# Defaults to true
azure_attribute_absence ["acr_not_allowing_unrestricted_network_access"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    not has_property(resource.properties, "public_network_access_enabled")
}

# Defaults to Allow
azure_attribute_absence ["acr_not_allowing_unrestricted_network_access"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    network_rule_set := resource.properties.network_rule_set[_]
    not network_rule_set.default_action
}

azure_issue ["acr_not_allowing_unrestricted_network_access"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    resource.properties.public_network_access_enabled == true
}

azure_issue ["acr_not_allowing_unrestricted_network_access"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    network_rule_set := resource.properties.network_rule_set[_]
    lower(network_rule_set.default_action) == "allow"
}

acr_not_allowing_unrestricted_network_access {
    lower(input.resources[_].type) == "azurerm_container_registry"
    not azure_attribute_absence["acr_not_allowing_unrestricted_network_access"]
    not azure_issue["acr_not_allowing_unrestricted_network_access"]
}

acr_not_allowing_unrestricted_network_access = false {
    azure_attribute_absence["acr_not_allowing_unrestricted_network_access"]
}

acr_not_allowing_unrestricted_network_access = false {
    azure_issue["acr_not_allowing_unrestricted_network_access"]
}

acr_not_allowing_unrestricted_network_access_err = "Azure Container registries currently allowing unrestricted network access" {
    azure_issue["acr_not_allowing_unrestricted_network_access"]
} else = "azurerm_container_registry property public_network_access_enabled and network_rule_set.default_action are missing from the resource" {
    azure_attribute_absence["acr_not_allowing_unrestricted_network_access"] 
}

acr_not_allowing_unrestricted_network_access_metadata := {
    "Policy Code": "PR-AZR-TRF-ACR-010",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Azure Container registries should not allow unrestricted network access",
    "Policy Description": "Azure container registries by default accept connections over the internet from hosts on any network. To protect your registries from potential threats, allow access from only specific private endpoints, public IP addresses or address ranges. If your registry doesn't have network rules configured, it will appear in the unhealthy resources. Learn more about Container Registry network rules here: https://aka.ms/acr/privatelink, https://aka.ms/acr/portal/public-network and https://aka.ms/acr/vnet.",
    "Resource Type": "azurerm_container_registry",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_registry"
}


# PR-AZR-TRF-ACR-011

default acr_configured_with_private_endpoint = null

azure_attribute_absence ["acr_configured_with_private_endpoint"] {
    count([c | input.resources[_].type == "azurerm_private_endpoint"; c := 1]) == 0
}

azure_issue ["acr_configured_with_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    count([c | r := input.resources[_];
              r.type == "azurerm_private_endpoint";
              contains(r.properties.private_service_connection[_].private_connection_resource_id, resource.properties.compiletime_identity);
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_private_endpoint";
              contains(r.properties.private_service_connection[_].private_connection_resource_id, concat(".", [resource.type, resource.name]));
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_private_endpoint";
              contains(r.properties.private_service_connection[_].private_connection_resource_alias, resource.properties.compiletime_identity);
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_private_endpoint";
              contains(r.properties.private_service_connection[_].private_connection_resource_alias, concat(".", [resource.type, resource.name]));
              c := 1]) == 0
}

acr_configured_with_private_endpoint = false {
    lower(input.resources[_].type) == "azurerm_container_registry"
    azure_attribute_absence["acr_configured_with_private_endpoint"]
}

acr_configured_with_private_endpoint {
    lower(input.resources[_].type) == "azurerm_container_registry"
    not azure_attribute_absence["acr_configured_with_private_endpoint"]
    not azure_issue["acr_configured_with_private_endpoint"]
}

acr_configured_with_private_endpoint = false {
    lower(input.resources[_].type) == "azurerm_container_registry"
    azure_issue["acr_configured_with_private_endpoint"]
}

acr_configured_with_private_endpoint_err = "azurerm_container_registry should have link with azurerm_private_endpoint and azurerm_private_endpoint's private_service_connection either need to have 'private_connection_resource_id' or 'private_connection_resource_alias' property. Seems there is no link established or mentioed properties are missing." {
    lower(input.resources[_].type) == "azurerm_container_registry"
    azure_attribute_absence["acr_configured_with_private_endpoint"]
} else = "MySQL server currently not using private link" {
    lower(input.resources[_].type) == "azurerm_container_registry"
    azure_issue["acr_configured_with_private_endpoint"]
}

acr_configured_with_private_endpoint_metadata := {
    "Policy Code": "PR-AZR-TRF-ACR-011",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Container registries should have private endpoints configured",
    "Policy Description": "Azure container registries by default accept connections over the internet from hosts on any network. To protect your registries from potential threats, allow access from only specific private endpoints, public IP addresses or address ranges. If your registry doesn't have network rules configured, it will appear in the unhealthy resources. Learn more about Container Registry network rules here: https://aka.ms/acr/privatelink, https://aka.ms/acr/portal/public-network and https://aka.ms/acr/vnet.",
    "Resource Type": "azurerm_container_registry",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_registry"
}

#
# PR-AZR-TRF-ACR-013
#
default acr_export_disabled = null

# Defaults to true
azure_attribute_absence ["acr_export_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    not has_property(resource.properties, "public_network_access_enabled")
}

# Defaults to true
azure_attribute_absence ["acr_export_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    not has_property(resource.properties, "export_policy_enabled")
}

azure_issue ["acr_export_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    resource.properties.public_network_access_enabled != false
}

azure_issue ["acr_export_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    resource.properties.export_policy_enabled != false
}

acr_export_disabled {
    lower(input.resources[_].type) == "azurerm_container_registry"
    not azure_attribute_absence["acr_export_disabled"]
    not azure_issue["acr_export_disabled"]
}

acr_export_disabled = false {
    azure_attribute_absence["acr_export_disabled"]
}

acr_export_disabled = false {
    azure_issue["acr_export_disabled"]
}

acr_export_disabled_err = "Azure Container registries currently dont have exports disabled" {
    azure_issue["acr_export_disabled"]
} else = "azurerm_container_registry property public_network_access_enabled and export_policy_enabled are missing from the resource" {
    azure_attribute_absence["acr_export_disabled"] 
}

acr_export_disabled_metadata := {
    "Policy Code": "PR-AZR-TRF-ACR-013",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Azure Container registries should have exports disabled",
    "Policy Description": "Disabling exports improves security by ensuring data in a registry is accessed solely via the dataplane ('docker pull'). Data cannot be moved out of the registry via 'acr import' or via 'acr transfer'. In order to disable exports, public network access must be disabled. Learn more at: https://aka.ms/acr/export-policy.",
    "Resource Type": "azurerm_container_registry",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_registry"
}


#
# PR-AZR-TRF-ACR-014
#
default acr_usage_custom_managed_key_for_encryption = null

azure_attribute_absence ["acr_usage_custom_managed_key_for_encryption"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    not resource.properties.encryption
}

azure_attribute_absence ["acr_usage_custom_managed_key_for_encryption"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    not resource.properties.encryption.enabled
}

azure_issue ["acr_usage_custom_managed_key_for_encryption"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    resource.properties.encryption.enabled != true
}

acr_usage_custom_managed_key_for_encryption {
    lower(input.resources[_].type) == "azurerm_container_registry"
    not azure_attribute_absence["acr_usage_custom_managed_key_for_encryption"]
    not azure_issue["acr_usage_custom_managed_key_for_encryption"]
}

acr_usage_custom_managed_key_for_encryption = false {
    azure_attribute_absence["acr_usage_custom_managed_key_for_encryption"]
}

acr_usage_custom_managed_key_for_encryption = false {
    azure_issue["acr_usage_custom_managed_key_for_encryption"]
}

acr_usage_custom_managed_key_for_encryption_err = "Azure Container registries currently dont use customer-managed key for encryption" {
    azure_issue["acr_usage_custom_managed_key_for_encryption"]
} else = "azurerm_container_registry property encryption.enabled is missing from the resource" {
    azure_attribute_absence["acr_usage_custom_managed_key_for_encryption"] 
}

acr_usage_custom_managed_key_for_encryption_metadata := {
    "Policy Code": "PR-AZR-TRF-ACR-014",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Container registries should be encrypted with a customer-managed key",
    "Policy Description": "Use customer-managed keys to manage the encryption at rest of the contents of your registries. By default, the data is encrypted at rest with service-managed keys, but customer-managed keys are commonly required to meet regulatory compliance standards. Customer-managed keys enable the data to be encrypted with an Azure Key Vault key created and owned by you. You have full control and responsibility for the key lifecycle, including rotation and management. Learn more at https://aka.ms/acr/CMK.Use customer-managed keys to manage the encryption at rest of the contents of your registries. By default, the data is encrypted at rest with service-managed keys, but customer-managed keys are commonly required to meet regulatory compliance standards. Customer-managed keys enable the data to be encrypted with an Azure Key Vault key created and owned by you. You have full control and responsibility for the key lifecycle, including rotation and management. Learn more at https://aka.ms/acr/CMK.Use customer-managed keys to manage the encryption at rest of the contents of your registries. By default, the data is encrypted at rest with service-managed keys, but customer-managed keys are commonly required to meet regulatory compliance standards. Customer-managed keys enable the data to be encrypted with an Azure Key Vault key created and owned by you. You have full control and responsibility for the key lifecycle, including rotation and management. Learn more at https://aka.ms/acr/CMK.",
    "Resource Type": "azurerm_container_registry",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_registry"
}