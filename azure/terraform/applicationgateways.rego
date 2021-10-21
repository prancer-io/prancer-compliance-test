package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_gateway

#
# PR-AZR-0011-TRF
#

default gw_tls = null

azure_attribute_absence["gw_tls"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    not resource.properties.ssl_policy
}

#azure_attribute_absence["gw_tls"] {
#    resource := input.resources[_]
#    lower(resource.type) == "azurerm_application_gateway"
#    count(resource.properties.ssl_policy) == 0
#}

azure_attribute_absence["gw_tls"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    ssl_policy := resource.properties.ssl_policy[_]
    not ssl_policy.min_protocol_version
}

azure_issue["gw_tls"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    ssl_policy := resource.properties.ssl_policy[_]
    lower(ssl_policy.min_protocol_version) != "tlsv1_2"
    lower(ssl_policy.min_protocol_version) != "tlsv1_3"
}

gw_tls {
    lower(input.resources[_].type) == "azurerm_application_gateway"
    not azure_attribute_absence["gw_tls"]
    not azure_issue["gw_tls"]
}

gw_tls = false {
    azure_attribute_absence["gw_tls"]
}

gw_tls = false {
    azure_issue["gw_tls"]
}

gw_tls_err = "azurerm_application_gateway property 'ssl_policy.min_protocol_version' need to be exist. Its missing from the resource. Please set the value to 'tlsv1_2' after property addition." {
    azure_attribute_absence["gw_tls"]
} else = "Azure Application Gateway is not using TLSv1.2 as minimum version or higher" {
    azure_issue["gw_tls"]
}

gw_tls_metadata := {
    "Policy Code": "PR-AZR-0011-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Application Gateway should use TLSv1.2 as minimum version or higher",
    "Policy Description": "The Application Gateway supports end-to-end SSL encryption using multiple TLS versions and by default, it supports TLS version 1.0 as the minimum version.<br><br>This policy identifies the Application Gateway instances that are configured to use TLS versions 1.1 or lower as the minimum protocol version. As a best practice set the MinProtocolVersion to TLSv1.2 (if you use custom SSL policy) or use the predefined â€˜AppGwSslPolicy20170401Sâ€™ policy.",
    "Resource Type": "azurerm_application_gateway",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_gateway"
}

#
# PR-AZR-0012-TRF
#

default gw_waf = null

azure_attribute_absence["gw_waf"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    not resource.properties.waf_configuration
}

#azure_attribute_absence["gw_waf"] {
#    resource := input.resources[_]
#    lower(resource.type) == "azurerm_application_gateway"
#    count(resource.properties.waf_configuration) == 0
#}

azure_attribute_absence["gw_waf"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    waf_configuration := resource.properties.waf_configuration[_]
    not waf_configuration.enabled
}

azure_issue["gw_waf"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    waf_configuration := resource.properties.waf_configuration[_]
    waf_configuration.enabled != true
}

gw_waf {
    lower(input.resources[_].type) == "azurerm_application_gateway"
    not azure_attribute_absence["gw_waf"]
    not azure_issue["gw_waf"]
}

gw_waf = false {
    azure_attribute_absence["gw_waf"]
}

gw_waf = false {
    azure_issue["gw_waf"]
} 

gw_waf_err = "azurerm_application_gateway property 'waf_configuration.enabled' need to be exist. Its missing from the resource. Please set the value to 'true' after property addition." {
    azure_attribute_absence["gw_waf"]
} else = "Azure Application Gateway does not have Web application firewall (WAF) enabled" {
    azure_issue["gw_waf"]
}

gw_waf_metadata := {
    "Policy Code": "PR-AZR-0012-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Application Gateway should have Web application firewall (WAF) enabled",
    "Policy Description": "This policy identifies Azure Application Gateways that do not have Web application firewall (WAF) enabled. As a best practice, enable WAF to manage and protect your web applications behind the Application Gateway from common exploits and vulnerabilities.",
    "Resource Type": "azurerm_application_gateway",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_gateway"
}

# PR-AZR-0125-TRF

default https_protocol = null

azure_attribute_absence ["https_protocol"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    not resource.properties.http_listener
} 

azure_attribute_absence ["https_protocol"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    http_listener := resource.properties.http_listener[_]
    not http_listener.protocol
}  

azure_issue ["https_protocol"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    http_listener := resource.properties.http_listener[_]
    lower(http_listener.protocol) != "https"
} 

https_protocol = false {
    azure_attribute_absence["https_protocol"]
}

https_protocol {
    lower(input.resources[_].type) == "azurerm_application_gateway"
    not azure_attribute_absence["https_protocol"]
    not azure_issue["https_protocol"]
}

https_protocol = false {
    azure_issue["https_protocol"]
}

https_protocol_err = "azurerm_application_gateway property 'http_listener.protocol' need to be exist. Its missing from the resource. Please set the value to 'https' after property addition." {
    azure_attribute_absence["https_protocol"]
} else = "Application Gateway is currently not using Https protocol" {
    azure_issue["https_protocol"]
}

https_protocol_metadata := {
    "Policy Code": "PR-AZR-0125-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Application Gateway is using Https protocol",
    "Policy Description": "Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.",
    "Resource Type": "azurerm_application_gateway",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_gateway"
}


# PR-AZR-0060-TRF

default frontendPublicIPConfigurationsDisabled = null
azure_attribute_absence ["frontendPublicIPConfigurationsDisabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    frontend_ip_configuration := resource.properties.frontend_ip_configuration[_]
    not frontend_ip_configuration.public_ip_address_id
}  

frontendPublicIPConfigurationsDisabled {
    azure_attribute_absence["frontendPublicIPConfigurationsDisabled"]
} 

frontendPublicIPConfigurationsDisabled = false {
    lower(input.resources[_].type) == "azurerm_application_gateway"
    not azure_attribute_absence["frontendPublicIPConfigurationsDisabled"]
}

frontendPublicIPConfigurationsDisabled_err = "Application Gateway is currently allowing public ip address in frontend IP Configurations" {
    lower(input.resources[_].type) == "azurerm_application_gateway"
    not azure_attribute_absence["frontendPublicIPConfigurationsDisabled"]
}

frontendPublicIPConfigurationsDisabled_metadata := {
    "Policy Code": "PR-AZR-0060-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Application Gateway frontendIPConfigurations does not have public ip configured",
    "Policy Description": "Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.",
    "Resource Type": "azurerm_application_gateway",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_gateway"
}


# PR-AZR-0095-TRF

default backend_https_protocol_enabled = null
azure_attribute_absence ["backend_https_protocol_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    backend_http_settings := resource.properties.backend_http_settings[_]
    not backend_http_settings.protocol
}  

azure_issue ["backend_https_protocol_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    backend_http_settings := resource.properties.backend_http_settings[_]
    lower(backend_http_settings.protocol) != "https"
} 

backend_https_protocol_enabled {
    lower(input.resources[_].type) == "azurerm_application_gateway"
    not azure_attribute_absence["backend_https_protocol_enabled"]
    not azure_issue["backend_https_protocol_enabled"]
}

backend_https_protocol_enabled = false {
    azure_issue["backend_https_protocol_enabled"]
}

backend_https_protocol_enabled = false {
    azure_attribute_absence["backend_https_protocol_enabled"]
}

backend_https_protocol_enabled_err = "'backend_http_settings' property 'protocol' is missing from 'azurerm_application_gateway' resource" {
    azure_attribute_absence["backend_https_protocol_enabled"]
} else = "Application Gateway backend is currently not using Https protocol" {
    azure_issue["backend_https_protocol_enabled"]
}

backend_https_protocol_enabled_metadata := {
    "Policy Code": "PR-AZR-0095-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Application Gateway Backend is using Https protocol",
    "Policy Description": "Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.",
    "Resource Type": "azurerm_application_gateway",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_gateway"
}


# PR-AZR-0099-TRF

default secret_certificate_is_in_keyvalut = null
azure_attribute_absence ["secret_certificate_is_in_keyvalut"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    ssl_certificate := resource.properties.ssl_certificate[_]
    not ssl_certificate.key_vault_secret_id
}  

secret_certificate_is_in_keyvalut {
    lower(input.resources[_].type) == "azurerm_application_gateway"
    not azure_attribute_absence["secret_certificate_is_in_keyvalut"]
}

secret_certificate_is_in_keyvalut = false {
    azure_attribute_absence["secret_certificate_is_in_keyvalut"]
} 

secret_certificate_is_in_keyvalut_err = "Application Gateway is currently not storing ssl certificates in keyvalut" {
    azure_attribute_absence["secret_certificate_is_in_keyvalut"]
}

secret_certificate_is_in_keyvalut_metadata := {
    "Policy Code": "PR-AZR-0099-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Application Gateway secret certificates stores in keyvault",
    "Policy Description": "This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert",
    "Resource Type": "azurerm_application_gateway",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_gateway"
}
