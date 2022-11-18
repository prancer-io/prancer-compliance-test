package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

# https://docs.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries

# PR-AZR-CLD-ACR-002

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
    "Policy Code": "PR-AZR-CLD-ACR-002",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure that admin user is disabled for Container Registry",
    "Policy Description": "The value that indicates whether the admin user is enabled. Each container registry includes an admin user account, which is disabled by default. You can enable the admin user and manage its credentials in the Azure portal, or by using the Azure CLI or other Azure tools. All users authenticating with the admin account appear as a single user with push and pull access to the registry. Changing or disabling this account disables registry access for all users who use its credentials.",
    "Resource Type": "microsoft.containerregistry/registries",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries"
}



#
# PR-AZR-CLD-ACR-003
#

default acr_classic = null

azure_attribute_absence["acr_classic"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    not resource.sku.name
}

azure_issue["acr_classic"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    lower(resource.sku.name) == "classic"
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
    "Policy Code": "PR-AZR-CLD-ACR-003",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Container Registry should not use the deprecated classic registry",
    "Policy Description": "This policy identifies an Azure Container Registry (ACR) that is using the classic SKU. The initial release of the Azure Container Registry (ACR) service that was offered as a classic SKU is being deprecated and will be unavailable after April 2019. As a best practice, upgrade your existing classic registry to a managed registry.<br><br>For more information, visit https://docs.microsoft.com/en-us/azure/container-registry/container-registry-upgrade",
    "Resource Type": "microsoft.containerregistry/registries",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/containerregistry/registries/list"
}


# PR-AZR-CLD-ACR-004

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
    "Policy Code": "PR-AZR-CLD-ACR-004",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure Azure Container Instance is configured with virtual network",
    "Policy Description": "This policy identifies Azure Container Instances (ACI) that are not configured with a virtual network. Making container instances public makes an internet routable network. By deploying container instances into an Azure virtual network, your containers can communicate securely with other resources in the virtual network. So it is recommended to configure all your container instances within a virtual network.<br><br>For more details:<br>https://docs.microsoft.com/en-us/azure/container-instances/container-instances-vnet",
    "Resource Type": "microsoft.containerinstance/containergroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.containerinstance/containergroups?tabs=json&pivots=deployment-language-arm-template"
}


# PR-AZR-CLD-ACR-005

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
    "Policy Code": "PR-AZR-CLD-ACR-005",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure Azure Container Instance is configured with managed identity",
    "Policy Description": "This policy identifies Azure Container Instances (ACI) that are not configured with the managed identity. The managed identity is authenticated with Azure AD, developers don't have to store any credentials in code. So It is recommended to configure managed identity on all your container instances.<br><br>For more details:<br>https://docs.microsoft.com/en-us/azure/container-instances/container-instances-managed-identity",
    "Resource Type": "microsoft.containerinstance/containergroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.containerinstance/containergroups?tabs=json&pivots=deployment-language-arm-template"
}


# PR-AZR-CLD-ACR-006

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
    "Policy Code": "PR-AZR-CLD-ACR-006",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure Azure Container registries public access to All networks is disabled",
    "Policy Description": "This policy identifies Azure Container registries which has Public access to All networks enabled. Azure ACR is used to store Docker container images which might contain sensitive information. It is highly recommended to restrict public access from allow access from Selected networks or make it Private by disabling the Public access.",
    "Resource Type": "Microsoft.ContainerRegistry/registries",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries?pivots=deployment-language-arm-template"
}


# PR-AZR-CLD-ACR-007

default acr_repository_scoped_access_token_disabled = null

azure_attribute_absence ["acr_repository_scoped_access_token_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries/tokens"
    not resource.properties.status
}

azure_issue ["acr_repository_scoped_access_token_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries/tokens"
    lower(resource.properties.status) != "disabled"
}

acr_repository_scoped_access_token_disabled {
    lower(input.resources[_].type) == "microsoft.containerregistry/registries/tokens"
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
} else = "Azure Container registries token property status is missing from the resource" {
    azure_attribute_absence["acr_repository_scoped_access_token_disabled"] 
}

acr_repository_scoped_access_token_disabled_metadata := {
    "Policy Code": "PR-AZR-CLD-ACR-007",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure Azure Container registries repository scoped access token is disabled",
    "Policy Description": "Disable repository scoped access tokens for your registry so that repositories are not accessible by tokens. Disabling local authentication methods like admin user, repository scoped access tokens and anonymous pull improves security by ensuring that container registries exclusively require Azure Active Directory identities for authentication. Learn more at: https://aka.ms/acr/authentication.",
    "Resource Type": "Microsoft.ContainerRegistry/registries/tokens",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries/tokens?pivots=deployment-language-arm-template"
}


# PR-AZR-CLD-ACR-008

default acr_has_premium_sku = null

azure_attribute_absence ["acr_has_premium_sku"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    not resource.properties.sku
}

azure_attribute_absence ["acr_has_premium_sku"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    not resource.properties.sku.name
}

azure_issue ["acr_has_premium_sku"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    lower(resource.properties.sku.name) != "premium"
}

acr_has_premium_sku {
    lower(input.resources[_].type) == "microsoft.containerregistry/registries"
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
} else = "Azure Container registries property sku.name is missing from the resource" {
    azure_attribute_absence["acr_has_premium_sku"] 
}

acr_has_premium_sku_metadata := {
    "Policy Code": "PR-AZR-CLD-ACR-008",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Container registries should have SKUs that support Private Links",
    "Policy Description": "Azure Private Link lets you connect your virtual network to Azure services without a public IP address at the source or destination. The private link platform handles the connectivity between the consumer and services over the Azure backbone network. By mapping private endpoints to your container registries instead of the entire service, data leakage risks are reduced. Learn more at: https://aka.ms/acr/private-link.",
    "Resource Type": "Microsoft.ContainerRegistry/registries",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries?pivots=deployment-language-arm-template"
}


# PR-AZR-CLD-ACR-009

default acr_anonymous_auth_disabled = null

azure_attribute_absence ["acr_anonymous_auth_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    not resource.properties.anonymousPullEnabled
}

azure_issue ["acr_anonymous_auth_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    resource.properties.anonymousPullEnabled == true
}

acr_anonymous_auth_disabled {
    lower(input.resources[_].type) == "microsoft.containerregistry/registries"
    not azure_attribute_absence["acr_anonymous_auth_disabled"]
    not azure_issue["acr_anonymous_auth_disabled"]
}

acr_anonymous_auth_disabled = false {
    azure_attribute_absence["acr_anonymous_auth_disabled"]
}

acr_anonymous_auth_disabled = false {
    azure_issue["acr_anonymous_auth_disabled"]
}

acr_anonymous_auth_disabled_err = "Azure Container registries anonymous authentication is currently not disabled" {
    azure_issue["acr_anonymous_auth_disabled"]
} else = "Azure Container registries property anonymousPullEnabled is missing from the resource" {
    azure_attribute_absence["acr_anonymous_auth_disabled"] 
}

acr_anonymous_auth_disabled_metadata := {
    "Policy Code": "PR-AZR-CLD-ACR-009",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure Azure Container registries has anonymous authentication disabled",
    "Policy Description": "Disable anonymous pull for your registry so that data not accessible by unauthenticated user. Disabling local authentication methods like admin user, repository scoped access tokens and anonymous pull improves security by ensuring that container registries exclusively require Azure Active Directory identities for authentication. Learn more at: https://aka.ms/acr/authentication.",
    "Resource Type": "Microsoft.ContainerRegistry/registries",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries?pivots=deployment-language-arm-template"
}


# PR-AZR-CLD-ACR-010

default acr_not_allowing_unrestricted_network_access = null

azure_attribute_absence ["acr_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    not resource.properties.publicNetworkAccess
}

azure_attribute_absence ["acr_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    not resource.properties.networkRuleSet.defaultAction
}

azure_issue ["acr_not_allowing_unrestricted_network_access"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    lower(resource.properties.publicNetworkAccess) != "disabled"
}

azure_issue ["acr_not_allowing_unrestricted_network_access"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    lower(resource.properties.networkRuleSet.defaultAction) == "allow"
}

acr_not_allowing_unrestricted_network_access {
    lower(input.resources[_].type) == "microsoft.containerregistry/registries"
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
} else = "Azure Container registries property publicNetworkAccess and networkRuleSet.defaultAction are missing from the resource" {
    azure_attribute_absence["acr_not_allowing_unrestricted_network_access"] 
}

acr_not_allowing_unrestricted_network_access_metadata := {
    "Policy Code": "PR-AZR-CLD-ACR-010",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure Azure Container registries should not allow unrestricted network access",
    "Policy Description": "Azure container registries by default accept connections over the internet from hosts on any network. To protect your registries from potential threats, allow access from only specific private endpoints, public IP addresses or address ranges. If your registry doesn't have network rules configured, it will appear in the unhealthy resources. Learn more about Container Registry network rules here: https://aka.ms/acr/privatelink, https://aka.ms/acr/portal/public-network and https://aka.ms/acr/vnet.",
    "Resource Type": "Microsoft.ContainerRegistry/registries",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries?pivots=deployment-language-arm-template"
}

# PR-AZR-CLD-ACR-011

default acr_configured_with_private_endpoint = null

azure_attribute_absence["acr_configured_with_private_endpoint"] {
    count([c | lower(input.resources[_].type) == "microsoft.containerregistry/registries/privateendpointconnections"; c := 1]) == 0
}

azure_attribute_absence["acr_configured_with_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries/privateendpointconnections"
    not resource.dependsOn
}

azure_attribute_absence["acr_configured_with_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries/privateendpointconnections"
    not resource.properties.privateLinkServiceConnectionState
}

azure_attribute_absence["acr_configured_with_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries/privateendpointconnections"
    not resource.properties.privateLinkServiceConnectionState.status
}

azure_issue["acr_configured_with_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.containerregistry/registries/privateendpointconnections";
              array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              lower(r.properties.privateLinkServiceConnectionState.status) == "approved";
              c := 1]) == 0
}

acr_configured_with_private_endpoint {
    lower(input.resources[_].type) == "microsoft.containerregistry/registries"
    not azure_attribute_absence["acr_configured_with_private_endpoint"]
    not azure_issue["acr_configured_with_private_endpoint"]
}

acr_configured_with_private_endpoint = false {
    lower(input.resources[_].type) == "microsoft.containerregistry/registries"
    azure_attribute_absence["acr_configured_with_private_endpoint"]
}

acr_configured_with_private_endpoint = false {
    lower(input.resources[_].type) == "microsoft.containerregistry/registries"
    azure_issue["acr_configured_with_private_endpoint"]
}

acr_configured_with_private_endpoint_err = "Azure Container registries currently dont have private endpoints configured" {
    lower(input.resources[_].type) == "microsoft.containerregistry/registries"
    azure_issue["acr_configured_with_private_endpoint"]
} else = "microsoft.containerregistry/registries/privateendpointconnections resoruce property 'privateLinkServiceConnectionState.status' is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.containerregistry/registries"
    azure_attribute_absence["acr_configured_with_private_endpoint"]
}

acr_configured_with_private_endpoint_metadata := {
    "Policy Code": "PR-AZR-CLD-ACR-011",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Container registries should have private endpoints configured",
    "Policy Description": "Azure container registries by default accept connections over the internet from hosts on any network. To protect your registries from potential threats, allow access from only specific private endpoints, public IP addresses or address ranges. If your registry doesn't have network rules configured, it will appear in the unhealthy resources. Learn more about Container Registry network rules here: https://aka.ms/acr/privatelink, https://aka.ms/acr/portal/public-network and https://aka.ms/acr/vnet.",
    "Resource Type": "Microsoft.ContainerRegistry/registries",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries?pivots=deployment-language-arm-template"
}


# PR-AZR-CLD-ACR-012

default acr_has_arm_audience_token_auth_disabled = null

azure_attribute_absence ["acr_has_arm_audience_token_auth_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    not resource.properties.policies.azureADAuthenticationAsArmPolicy
}

azure_attribute_absence ["acr_has_arm_audience_token_auth_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    not resource.properties.policies.azureADAuthenticationAsArmPolicy.status
}

azure_issue ["acr_has_arm_audience_token_auth_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    lower(resource.properties.policies.azureADAuthenticationAsArmPolicy.status) == "enabled"
}

acr_has_arm_audience_token_auth_disabled {
    lower(input.resources[_].type) == "microsoft.containerregistry/registries"
    not azure_attribute_absence["acr_has_arm_audience_token_auth_disabled"]
    not azure_issue["acr_has_arm_audience_token_auth_disabled"]
}

acr_has_arm_audience_token_auth_disabled = false {
    azure_attribute_absence["acr_has_arm_audience_token_auth_disabled"]
}

acr_has_arm_audience_token_auth_disabled = false {
    azure_issue["acr_has_arm_audience_token_auth_disabled"]
}

acr_has_arm_audience_token_auth_disabled_err = "Azure Container registries currently dont have ARM audience token authentication disabled" {
    azure_issue["acr_has_arm_audience_token_auth_disabled"]
} else = "Azure Container registries property policies.azureADAuthenticationAsArmPolicy.status is missing from the resource" {
    azure_attribute_absence["acr_has_arm_audience_token_auth_disabled"] 
}

acr_has_arm_audience_token_auth_disabled_metadata := {
    "Policy Code": "PR-AZR-CLD-ACR-012",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Container registries should have ARM audience token authentication disabled",
    "Policy Description": "Disable Azure Active Directory ARM audience tokens for authentication to your registry. Only Azure Container Registry (ACR) audience tokens will be used for authentication. This will ensure only tokens meant for usage on the registry can be used for authentication. Disabling ARM audience tokens does not affect admin user's or scoped access tokens' authentication. Learn more at: https://aka.ms/acr/authentication.",
    "Resource Type": "Microsoft.ContainerRegistry/registries",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries?pivots=deployment-language-arm-template"
}


# PR-AZR-CLD-ACR-013

default acr_export_disabled = null

azure_attribute_absence ["acr_export_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    not resource.properties.publicNetworkAccess
}

azure_attribute_absence ["acr_export_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    not resource.properties.policies.exportPolicy.status
}

azure_issue ["acr_export_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    lower(resource.properties.publicNetworkAccess) != "disabled"
}

azure_issue ["acr_export_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    lower(resource.properties.policies.exportPolicy.status) != "disabled"
}

acr_export_disabled {
    lower(input.resources[_].type) == "microsoft.containerregistry/registries"
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
} else = "Azure Container registries property publicNetworkAccess and policies.exportPolicy.status are missing from the resource" {
    azure_attribute_absence["acr_export_disabled"] 
}

acr_export_disabled_metadata := {
    "Policy Code": "PR-AZR-CLD-ACR-013",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure Azure Container registries should have exports disabled",
    "Policy Description": "Disabling exports improves security by ensuring data in a registry is accessed solely via the dataplane ('docker pull'). Data cannot be moved out of the registry via 'acr import' or via 'acr transfer'. In order to disable exports, public network access must be disabled. Learn more at: https://aka.ms/acr/export-policy.",
    "Resource Type": "Microsoft.ContainerRegistry/registries",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries?pivots=deployment-language-arm-template"
}


# PR-AZR-CLD-ACR-014

default acr_usage_custom_managed_key_for_encryption = null

azure_attribute_absence ["acr_usage_custom_managed_key_for_encryption"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    not resource.properties.encryption
}

azure_attribute_absence ["acr_usage_custom_managed_key_for_encryption"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    not resource.properties.encryption.status
}

azure_issue ["acr_usage_custom_managed_key_for_encryption"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    lower(resource.properties.encryption.status) != "enabled"
}

acr_usage_custom_managed_key_for_encryption {
    lower(input.resources[_].type) == "microsoft.containerregistry/registries"
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
} else = "Azure Container registries property encryption.status is missing from the resource" {
    azure_attribute_absence["acr_usage_custom_managed_key_for_encryption"] 
}

acr_usage_custom_managed_key_for_encryption_metadata := {
    "Policy Code": "PR-AZR-CLD-ACR-014",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Container registries should be encrypted with a customer-managed key",
    "Policy Description": "Use customer-managed keys to manage the encryption at rest of the contents of your registries. By default, the data is encrypted at rest with service-managed keys, but customer-managed keys are commonly required to meet regulatory compliance standards. Customer-managed keys enable the data to be encrypted with an Azure Key Vault key created and owned by you. You have full control and responsibility for the key lifecycle, including rotation and management. Learn more at https://aka.ms/acr/CMK.Use customer-managed keys to manage the encryption at rest of the contents of your registries. By default, the data is encrypted at rest with service-managed keys, but customer-managed keys are commonly required to meet regulatory compliance standards. Customer-managed keys enable the data to be encrypted with an Azure Key Vault key created and owned by you. You have full control and responsibility for the key lifecycle, including rotation and management. Learn more at https://aka.ms/acr/CMK.Use customer-managed keys to manage the encryption at rest of the contents of your registries. By default, the data is encrypted at rest with service-managed keys, but customer-managed keys are commonly required to meet regulatory compliance standards. Customer-managed keys enable the data to be encrypted with an Azure Key Vault key created and owned by you. You have full control and responsibility for the key lifecycle, including rotation and management. Learn more at https://aka.ms/acr/CMK.",
    "Resource Type": "Microsoft.ContainerRegistry/registries",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries?pivots=deployment-language-arm-template"
}