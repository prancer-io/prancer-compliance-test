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

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_group
#
# PR-AZR-TRF-ACR-004
#

default aci_configured_with_vnet = null

azure_attribute_absence["aci_configured_with_vnet"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_group"
    not resource.properties.ip_address_type
}

azure_issue["aci_configured_with_vnet"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_group"
    lower(resource.properties.ip_address_type) != "private"
}

aci_configured_with_vnet {
    lower(input.resources[_].type) == "azurerm_container_group"
    not azure_attribute_absence["aci_configured_with_vnet"]
    not azure_issue["aci_configured_with_vnet"]
}

aci_configured_with_vnet = false {
    azure_attribute_absence["aci_configured_with_vnet"]
}

aci_configured_with_vnet = false {
    azure_issue["aci_configured_with_vnet"]
}

aci_configured_with_vnet_err = "azurerm_container_group property 'ip_address_type' need to be exist. Its missing from the resource." {
    azure_attribute_absence["aci_configured_with_vnet"]
} else = "Azure Container Instance is currently not configured with virtual network" {
    azure_issue["aci_configured_with_vnet"]
}

aci_configured_with_vnet_metadata := {
    "Policy Code": "PR-AZR-TRF-ACR-004",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Azure Container Instance is configured with virtual network",
    "Policy Description": "This policy identifies Azure Container Instances (ACI) that are not configured with a virtual network. Making container instances public makes an internet routable network. By deploying container instances into an Azure virtual network, your containers can communicate securely with other resources in the virtual network. So it is recommended to configure all your container instances within a virtual network.<br><br>For more details:<br>https://docs.microsoft.com/en-us/azure/container-instances/container-instances-vnet",
    "Resource Type": "azurerm_container_group",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_group"
}

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_group
#
# PR-AZR-TRF-ACR-005
#

default aci_configured_with_managed_identity = null

azure_attribute_absence["aci_configured_with_managed_identity"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_group"
    not resource.properties.identity 
}

azure_attribute_absence["aci_configured_with_managed_identity"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_group"
    identity := resource.properties.identity[_]
    not identity.type
}

azure_issue["aci_configured_with_managed_identity"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_group"
    identity := resource.properties.identity[_]
    lower(identity.type) == ""
}

azure_issue["aci_configured_with_managed_identity"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_group"
    identity := resource.properties.identity[_]
    lower(identity.type) == "none"
}

aci_configured_with_managed_identity {
    lower(input.resources[_].type) == "azurerm_container_group"
    not azure_attribute_absence["aci_configured_with_managed_identity"]
    not azure_issue["aci_configured_with_managed_identity"]
}

aci_configured_with_managed_identity = false {
    azure_attribute_absence["aci_configured_with_managed_identity"]
}

aci_configured_with_managed_identity = false {
    azure_issue["aci_configured_with_managed_identity"]
}

aci_configured_with_managed_identity_err = "azurerm_container_group property 'identity.type' need to be exist. Its missing from the resource." {
    azure_attribute_absence["aci_configured_with_managed_identity"]
} else = "Azure Container Instance is currently not configured with managed identity" {
    azure_issue["aci_configured_with_managed_identity"]
}

aci_configured_with_managed_identity_metadata := {
    "Policy Code": "PR-AZR-TRF-ACR-005",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Azure Container Instance is configured with managed identity",
    "Policy Description": "This policy identifies Azure Container Instances (ACI) that are not configured with the managed identity. The managed identity is authenticated with Azure AD, developers don't have to store any credentials in code. So It is recommended to configure managed identity on all your container instances.<br><br>For more details:<br>https://docs.microsoft.com/en-us/azure/container-instances/container-instances-managed-identity",
    "Resource Type": "azurerm_container_group",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_group"
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