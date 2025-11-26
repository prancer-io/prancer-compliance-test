package rule

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }

# https://learn.microsoft.com/en-us/azure/templates/microsoft.eventgrid/topics?pivots=deployment-language-arm-template

#
# PR-AZR-ARM-EGR-001
#

default event_grid_topic_has_public_network_access_disabled = null
# By default it is enabled.
azure_attribute_absence["event_grid_topic_has_public_network_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventgrid/topics"
    not resource.properties.publicNetworkAccess
}

azure_issue["event_grid_topic_has_public_network_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventgrid/topics"
    resource.properties.publicNetworkAccess != "disabled"
}

event_grid_topic_has_public_network_access_disabled {
    lower(input.resources[_].type) == "microsoft.eventgrid/topics"
    not azure_attribute_absence["event_grid_topic_has_public_network_access_disabled"]
    not azure_issue["event_grid_topic_has_public_network_access_disabled"]
}

event_grid_topic_has_public_network_access_disabled = false {
    azure_attribute_absence["event_grid_topic_has_public_network_access_disabled"]
}

event_grid_topic_has_public_network_access_disabled = false {
    azure_issue["event_grid_topic_has_public_network_access_disabled"]
}

event_grid_topic_has_public_network_access_disabled_err = "microsoft.eventgrid/topics resoruce property publicNetworkAccess is missing" {
    azure_attribute_absence["event_grid_topic_has_public_network_access_disabled"]
} else = "Azure Event Grid topics public network access is currently not disabled" {
    azure_issue["event_grid_topic_has_public_network_access_disabled"]
}

event_grid_topic_has_public_network_access_disabled_metadata := {
    "Policy Code": "PR-AZR-ARM-EGR-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Event Grid topics should disable public network access",
    "Policy Description": "Disabling public network access improves security by ensuring that the resource isn't exposed on the public internet. You can limit exposure of your resources by creating private endpoints instead. Learn more at: https://aka.ms/privateendpoints.",
    "Resource Type": "microsoft.eventgrid/topics",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.eventgrid/topics?pivots=deployment-language-arm-template"
}


#
# PR-AZR-ARM-EGR-002
#

default event_grid_topic_has_local_auth_disabled = null
# Default value is false
azure_attribute_absence["event_grid_topic_has_local_auth_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventgrid/topics"
    not resource.properties.disableLocalAuth
}

azure_issue["event_grid_topic_has_local_auth_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventgrid/topics"
    resource.properties.disableLocalAuth != true
}

event_grid_topic_has_local_auth_disabled {
    lower(input.resources[_].type) == "microsoft.eventgrid/topics"
    not azure_attribute_absence["event_grid_topic_has_local_auth_disabled"]
    not azure_issue["event_grid_topic_has_local_auth_disabled"]
}

event_grid_topic_has_local_auth_disabled = false {
    azure_attribute_absence["event_grid_topic_has_local_auth_disabled"]
}

event_grid_topic_has_local_auth_disabled = false {
    azure_issue["event_grid_topic_has_local_auth_disabled"]
}

event_grid_topic_has_local_auth_disabled_err = "microsoft.eventgrid/topics resoruce property disableLocalAuth is missing" {
    azure_attribute_absence["event_grid_topic_has_local_auth_disabled"]
} else = "Azure Event Grid topics local authentication is currently not disabled" {
    azure_issue["event_grid_topic_has_local_auth_disabled"]
}

event_grid_topic_has_local_auth_disabled_metadata := {
    "Policy Code": "PR-AZR-ARM-EGR-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Event Grid topics should disable local authentication",
    "Policy Description": "Disable local authentication methods so that your Azure Event Grid topics exclusively require Azure Active Directory identities for authentication. Learn more at: https://aka.ms/aeg-disablelocalauth.",
    "Resource Type": "microsoft.eventgrid/topics",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.eventgrid/topics?pivots=deployment-language-arm-template"
}

# https://learn.microsoft.com/en-us/azure/templates/microsoft.eventgrid/domains/privateendpointconnections?pivots=deployment-language-arm-template
# PR-AZR-ARM-EGR-003

default event_grid_domain_configured_with_private_endpoint = null

azure_attribute_absence["event_grid_domain_configured_with_private_endpoint"] {
    count([c | lower(input.resources[_].type) == "microsoft.eventgrid/domains/privateendpointconnections"; c := 1]) == 0
}

azure_attribute_absence["event_grid_domain_configured_with_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventgrid/domains/privateendpointconnections"
    not resource.dependsOn
}

azure_attribute_absence["event_grid_domain_configured_with_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventgrid/domains/privateendpointconnections"
    not resource.properties.privateLinkServiceConnectionState
}

azure_attribute_absence["event_grid_domain_configured_with_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventgrid/domains/privateendpointconnections"
    not resource.properties.privateLinkServiceConnectionState.status
}

azure_issue["event_grid_domain_configured_with_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventgrid/domains"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.eventgrid/domains/privateendpointconnections";
              array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              lower(r.properties.privateLinkServiceConnectionState.status) == "approved";
              c := 1]) == 0
}

event_grid_domain_configured_with_private_endpoint {
    lower(input.resources[_].type) == "microsoft.eventgrid/domains"
    not azure_attribute_absence["event_grid_domain_configured_with_private_endpoint"]
    not azure_issue["event_grid_domain_configured_with_private_endpoint"]
}

event_grid_domain_configured_with_private_endpoint = false {
    lower(input.resources[_].type) == "microsoft.eventgrid/domains"
    azure_attribute_absence["event_grid_domain_configured_with_private_endpoint"]
}

event_grid_domain_configured_with_private_endpoint = false {
    lower(input.resources[_].type) == "microsoft.eventgrid/domains"
    azure_issue["event_grid_domain_configured_with_private_endpoint"]
}

event_grid_domain_configured_with_private_endpoint_err = "Azure Event Grid domains currently dont have private endpoints configured" {
    lower(input.resources[_].type) == "microsoft.eventgrid/domains"
    azure_issue["event_grid_domain_configured_with_private_endpoint"]
} else = "Microsoft.EventGrid/domains/privateEndpointConnections resoruce property 'privateLinkServiceConnectionState.status' is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.eventgrid/domains"
    azure_attribute_absence["event_grid_domain_configured_with_private_endpoint"]
}

event_grid_domain_configured_with_private_endpoint_metadata := {
    "Policy Code": "PR-AZR-ARM-EGR-003",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Event Grid domains should have private endpoints configured",
    "Policy Description": "Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your resources, they'll be protected against data leakage risks. Learn more at: https://aka.ms/privateendpoints.",
    "Resource Type": "microsoft.eventgrid/domains",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.eventgrid/domains?pivots=deployment-language-arm-template"
}


# https://learn.microsoft.com/en-us/azure/templates/microsoft.eventgrid/topics/privateendpointconnections?pivots=deployment-language-arm-template
# PR-AZR-ARM-EGR-004

default event_grid_topic_configured_with_private_endpoint = null

azure_attribute_absence["event_grid_topic_configured_with_private_endpoint"] {
    count([c | lower(input.resources[_].type) == "microsoft.eventgrid/topics/privateendpointconnections"; c := 1]) == 0
}

azure_attribute_absence["event_grid_topic_configured_with_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventgrid/topics/privateendpointconnections"
    not resource.dependsOn
}

azure_attribute_absence["event_grid_topic_configured_with_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventgrid/topics/privateendpointconnections"
    not resource.properties.privateLinkServiceConnectionState
}

azure_attribute_absence["event_grid_topic_configured_with_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventgrid/topics/privateendpointconnections"
    not resource.properties.privateLinkServiceConnectionState.status
}

azure_issue["event_grid_topic_configured_with_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventgrid/topics"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.eventgrid/topics/privateendpointconnections";
              array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              lower(r.properties.privateLinkServiceConnectionState.status) == "approved";
              c := 1]) == 0
}

event_grid_topic_configured_with_private_endpoint {
    lower(input.resources[_].type) == "microsoft.eventgrid/topics"
    not azure_attribute_absence["event_grid_topic_configured_with_private_endpoint"]
    not azure_issue["event_grid_topic_configured_with_private_endpoint"]
}

event_grid_topic_configured_with_private_endpoint = false {
    lower(input.resources[_].type) == "microsoft.eventgrid/topics"
    azure_attribute_absence["event_grid_topic_configured_with_private_endpoint"]
}

event_grid_topic_configured_with_private_endpoint = false {
    lower(input.resources[_].type) == "microsoft.eventgrid/topics"
    azure_issue["event_grid_topic_configured_with_private_endpoint"]
}

event_grid_topic_configured_with_private_endpoint_err = "Azure Event Grid topics currently dont have private endpoints configured" {
    lower(input.resources[_].type) == "microsoft.eventgrid/topics"
    azure_issue["event_grid_topic_configured_with_private_endpoint"]
} else = "microsoft.eventgrid/topics/privateendpointconnections resoruce property 'privateLinkServiceConnectionState.status' is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.eventgrid/topics"
    azure_attribute_absence["event_grid_topic_configured_with_private_endpoint"]
}

event_grid_topic_configured_with_private_endpoint_metadata := {
    "Policy Code": "PR-AZR-ARM-EGR-004",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Event Grid topics should have private endpoints configured",
    "Policy Description": "Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your resources, they'll be protected against data leakage risks. Learn more at: https://aka.ms/privateendpoints.",
    "Resource Type": "Microsoft.EventGrid/topics",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.eventgrid/topics?pivots=deployment-language-arm-template"
}


#
# PR-AZR-ARM-EGR-005
#

default event_grid_domain_has_public_network_access_disabled = null
# By default it is enabled.
azure_attribute_absence["event_grid_domain_has_public_network_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventgrid/domains"
    not resource.properties.publicNetworkAccess
}

azure_issue["event_grid_domain_has_public_network_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventgrid/domains"
    resource.properties.publicNetworkAccess != "disabled"
}

event_grid_domain_has_public_network_access_disabled {
    lower(input.resources[_].type) == "microsoft.eventgrid/domains"
    not azure_attribute_absence["event_grid_domain_has_public_network_access_disabled"]
    not azure_issue["event_grid_domain_has_public_network_access_disabled"]
}

event_grid_domain_has_public_network_access_disabled = false {
    azure_attribute_absence["event_grid_domain_has_public_network_access_disabled"]
}

event_grid_domain_has_public_network_access_disabled = false {
    azure_issue["event_grid_domain_has_public_network_access_disabled"]
}

event_grid_domain_has_public_network_access_disabled_err = "microsoft.eventgrid/domains resoruce property publicNetworkAccess is missing" {
    azure_attribute_absence["event_grid_domain_has_public_network_access_disabled"]
} else = "Azure Event Grid domains public network access is currently not disabled" {
    azure_issue["event_grid_domain_has_public_network_access_disabled"]
}

event_grid_domain_has_public_network_access_disabled_metadata := {
    "Policy Code": "PR-AZR-ARM-EGR-005",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Event Grid domains should disable public network access",
    "Policy Description": "Disable public network access for Azure Event Grid resource so that it isn't accessible over the public internet. This will help protect them against data leakage risks. You can limit exposure of your resources by creating private endpoints instead. Learn more at: https://aka.ms/privateendpoints.",
    "Resource Type": "microsoft.eventgrid/domains",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.eventgrid/domains?pivots=deployment-language-arm-template"
}


#
# PR-AZR-ARM-EGR-006
#

default event_grid_domain_has_local_auth_disabled = null
# Default value is false
azure_attribute_absence["event_grid_domain_has_local_auth_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventgrid/domains"
    not resource.properties.disableLocalAuth
}

azure_issue["event_grid_domain_has_local_auth_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventgrid/domains"
    resource.properties.disableLocalAuth != true
}

event_grid_domain_has_local_auth_disabled {
    lower(input.resources[_].type) == "microsoft.eventgrid/domains"
    not azure_attribute_absence["event_grid_domain_has_local_auth_disabled"]
    not azure_issue["event_grid_domain_has_local_auth_disabled"]
}

event_grid_domain_has_local_auth_disabled = false {
    azure_attribute_absence["event_grid_domain_has_local_auth_disabled"]
}

event_grid_domain_has_local_auth_disabled = false {
    azure_issue["event_grid_domain_has_local_auth_disabled"]
}

event_grid_domain_has_local_auth_disabled_err = "microsoft.eventgrid/domains resoruce property disableLocalAuth is missing" {
    azure_attribute_absence["event_grid_domain_has_local_auth_disabled"]
} else = "Azure Event Grid domains local authentication is currently not disabled" {
    azure_issue["event_grid_domain_has_local_auth_disabled"]
}

event_grid_domain_has_local_auth_disabled_metadata := {
    "Policy Code": "PR-AZR-ARM-EGR-006",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Event Grid domains should disable local authentication",
    "Policy Description": "Disable local authentication methods so that your Azure Event Grid domains exclusively require Azure Active Directory identities for authentication. Learn more at: https://aka.ms/aeg-disablelocalauth.",
    "Resource Type": "microsoft.eventgrid/domains",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.eventgrid/domains?pivots=deployment-language-arm-template"
}


#
# PR-AZR-ARM-EGR-009
#

default event_grid_partnernamespace_has_local_auth_disabled = null
# Default value is false
azure_attribute_absence["event_grid_partnernamespace_has_local_auth_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventgrid/partnernamespaces"
    not resource.properties.disableLocalAuth
}

azure_issue["event_grid_partnernamespace_has_local_auth_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventgrid/partnernamespaces"
    resource.properties.disableLocalAuth != true
}

event_grid_partnernamespace_has_local_auth_disabled {
    lower(input.resources[_].type) == "microsoft.eventgrid/partnernamespaces"
    not azure_attribute_absence["event_grid_partnernamespace_has_local_auth_disabled"]
    not azure_issue["event_grid_partnernamespace_has_local_auth_disabled"]
}

event_grid_partnernamespace_has_local_auth_disabled = false {
    azure_attribute_absence["event_grid_partnernamespace_has_local_auth_disabled"]
}

event_grid_partnernamespace_has_local_auth_disabled = false {
    azure_issue["event_grid_partnernamespace_has_local_auth_disabled"]
}

event_grid_partnernamespace_has_local_auth_disabled_err = "microsoft.eventgrid/partnernamespaces resoruce property disableLocalAuth is missing" {
    azure_attribute_absence["event_grid_partnernamespace_has_local_auth_disabled"]
} else = "Azure Event Grid partner namespaces local authentication is currently not disabled" {
    azure_issue["event_grid_partnernamespace_has_local_auth_disabled"]
}

event_grid_partnernamespace_has_local_auth_disabled_metadata := {
    "Policy Code": "PR-AZR-ARM-EGR-009",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Event Grid partner namespaces should disable local authentication",
    "Policy Description": "Disabling local authentication methods improves security by ensuring that Azure Event Grid partner namespaces exclusively require Azure Active Directory identities for authentication. Learn more at: https://aka.ms/aeg-disablelocalauth.",
    "Resource Type": "microsoft.eventgrid/partnernamespaces",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.eventgrid/partnernamespaces?pivots=deployment-language-arm-template"
}