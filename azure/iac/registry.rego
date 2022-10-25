package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

# https://docs.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries

# PR-AZR-ARM-ACR-002

default adminUserDisabled = null

azure_attribute_absence ["adminUserDisabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    not has_property(resource.properties, "adminUserEnabled")
}

azure_issue ["adminUserDisabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    resource.properties.adminUserEnabled != false
}

adminUserDisabled {
    lower(input.resources[_].type) == "microsoft.containerregistry/registries"
    not azure_attribute_absence["adminUserDisabled"]
    not azure_issue["adminUserDisabled"]
}

adminUserDisabled {
    azure_attribute_absence["adminUserDisabled"]
}

adminUserDisabled = false {
    azure_issue["adminUserDisabled"]
}

adminUserDisabled_err = "Azure Container Registry admin user is currently not disabled" {
    azure_issue["adminUserDisabled"]
}

adminUserDisabled_metadata := {
    "Policy Code": "PR-AZR-ARM-ACR-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that admin user is disabled for Container Registry",
    "Policy Description": "The value that indicates whether the admin user is enabled. Each container registry includes an admin user account, which is disabled by default. You can enable the admin user and manage its credentials in the Azure portal, or by using the Azure CLI or other Azure tools. All users authenticating with the admin account appear as a single user with push and pull access to the registry. Changing or disabling this account disables registry access for all users who use its credentials.",
    "Resource Type": "microsoft.containerregistry/registries",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries"
}



#
# PR-AZR-ARM-ACR-003
#

default acr_classic = null

azure_attribute_absence["acr_classic"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    not resource.sku.name
}

source_path[{"acr_classic":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.containerregistry/registries"
    not resource.sku.name
    metadata:= {
        "resource_path": [["resources",i,"sku","name"]]
    }
}

azure_issue["acr_classic"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    lower(resource.sku.name) == "classic"
}

source_path[{"acr_classic":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.containerregistry/registries"
    lower(resource.sku.name) == "classic"
    metadata:= {
        "resource_path": [["resources",i,"sku","name"]]
    }
}

acr_classic {
    lower(input.resources[_].type) == "microsoft.containerregistry/registries"
    not azure_attribute_absence["acr_classic"]
    not azure_issue["acr_classic"]
}

acr_classic = false {
    azure_issue["acr_classic"]
}

acr_classic = false {
    azure_attribute_absence["acr_classic"]
}

acr_classic_err = "Azure Container Registry currently configured with deprecated classic registry. Please change the SKU" {
    azure_issue["acr_classic"]
} else = "Azure Container registry property sku.name is missing from the resource" {
    azure_attribute_absence["acr_classic"]
}

acr_classic_metadata := {
    "Policy Code": "PR-AZR-ARM-ACR-003",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Container Registry should not use the deprecated classic registry",
    "Policy Description": "This policy identifies an Azure Container Registry (ACR) that is using the classic SKU. The initial release of the Azure Container Registry (ACR) service that was offered as a classic SKU is being deprecated and will be unavailable after April 2019. As a best practice, upgrade your existing classic registry to a managed registry.<br><br>For more information, visit https://docs.microsoft.com/en-us/azure/container-registry/container-registry-upgrade",
    "Resource Type": "microsoft.containerregistry/registries",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/containerregistry/registries/list"
}


# PR-AZR-ARM-ACR-004

default aci_configured_with_vnet = null

azure_attribute_absence ["aci_configured_with_vnet"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerinstance/containergroups"
    not resource.properties.ipAddress.type
}

azure_issue ["aci_configured_with_vnet"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerinstance/containergroups"
    lower(resource.properties.ipAddress.type) != "private"
}

aci_configured_with_vnet {
    lower(input.resources[_].type) == "microsoft.containerinstance/containergroups"
    not azure_attribute_absence["aci_configured_with_vnet"]
    not azure_issue["aci_configured_with_vnet"]
}

aci_configured_with_vnet = false {
    azure_attribute_absence["aci_configured_with_vnet"]
}

aci_configured_with_vnet = false {
    azure_issue["aci_configured_with_vnet"]
}

aci_configured_with_vnet_err = "Azure Container Instance is currently not configured with virtual network" {
    azure_issue["aci_configured_with_vnet"]
} else = "Azure Container Instance property ipAddress.type is missing from the resource" {
    azure_attribute_absence["aci_configured_with_vnet"] 
}

aci_configured_with_vnet_metadata := {
    "Policy Code": "PR-AZR-ARM-ACR-004",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure Azure Container Instance is configured with virtual network",
    "Policy Description": "This policy identifies Azure Container Instances (ACI) that are not configured with a virtual network. Making container instances public makes an internet routable network. By deploying container instances into an Azure virtual network, your containers can communicate securely with other resources in the virtual network. So it is recommended to configure all your container instances within a virtual network.<br><br>For more details:<br>https://docs.microsoft.com/en-us/azure/container-instances/container-instances-vnet",
    "Resource Type": "microsoft.containerinstance/containergroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.containerinstance/containergroups?tabs=json&pivots=deployment-language-arm-template"
}


# PR-AZR-ARM-ACR-005

default aci_configured_with_managed_identity = null

azure_attribute_absence ["aci_configured_with_managed_identity"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerinstance/containergroups"
    not resource.identity.type
}

azure_issue ["aci_configured_with_managed_identity"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerinstance/containergroups"
    lower(resource.identity.type) == "none"
}

aci_configured_with_managed_identity {
    lower(input.resources[_].type) == "microsoft.containerinstance/containergroups"
    not azure_attribute_absence["aci_configured_with_managed_identity"]
    not azure_issue["aci_configured_with_managed_identity"]
}

aci_configured_with_managed_identity = false {
    azure_attribute_absence["aci_configured_with_managed_identity"]
}

aci_configured_with_managed_identity = false {
    azure_issue["aci_configured_with_managed_identity"]
}

aci_configured_with_managed_identity_err = "Azure Container Instance is currently not configured with managed identity" {
    azure_issue["aci_configured_with_managed_identity"]
} else = "Azure Container Instance identity.type is missing from the resource" {
    azure_attribute_absence["aci_configured_with_managed_identity"] 
}

aci_configured_with_managed_identity_metadata := {
    "Policy Code": "PR-AZR-ARM-ACR-005",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure Azure Container Instance is configured with managed identity",
    "Policy Description": "This policy identifies Azure Container Instances (ACI) that are not configured with the managed identity. The managed identity is authenticated with Azure AD, developers don't have to store any credentials in code. So It is recommended to configure managed identity on all your container instances.<br><br>For more details:<br>https://docs.microsoft.com/en-us/azure/container-instances/container-instances-managed-identity",
    "Resource Type": "microsoft.containerinstance/containergroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.containerinstance/containergroups?tabs=json&pivots=deployment-language-arm-template"
}


# PR-AZR-ARM-ACR-006

default acr_public_access_disabled = null

azure_attribute_absence ["acr_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    not resource.properties.publicNetworkAccess
}

azure_issue ["acr_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    lower(resource.properties.publicNetworkAccess) != "disabled"
}

acr_public_access_disabled {
    lower(input.resources[_].type) == "microsoft.containerregistry/registries"
    not azure_attribute_absence["acr_public_access_disabled"]
    not azure_issue["acr_public_access_disabled"]
}

acr_public_access_disabled = false {
    azure_attribute_absence["acr_public_access_disabled"]
}

acr_public_access_disabled = false {
    azure_issue["acr_public_access_disabled"]
}

acr_public_access_disabled_err = "Azure Container registries public access to All networks is currently not disabled" {
    azure_issue["acr_public_access_disabled"]
} else = "Azure Container registries property publicNetworkAccess is missing from the resource" {
    azure_attribute_absence["acr_public_access_disabled"] 
}

acr_public_access_disabled_metadata := {
    "Policy Code": "PR-AZR-ARM-ACR-006",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure Azure Container registries public access to All networks is disabled",
    "Policy Description": "This policy identifies Azure Container registries which has Public access to All networks enabled. Azure ACR is used to store Docker container images which might contain sensitive information. It is highly recommended to restrict public access from allow access from Selected networks or make it Private by disabling the Public access.",
    "Resource Type": "Microsoft.ContainerRegistry/registries",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries?pivots=deployment-language-arm-template"
}