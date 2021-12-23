package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_gateway

#
# PR-AZR-TRF-AGW-001
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
    "Policy Code": "PR-AZR-TRF-AGW-001",
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
# PR-AZR-TRF-AGW-002
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
    "Policy Code": "PR-AZR-TRF-AGW-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Application Gateway should have Web application firewall (WAF) enabled",
    "Policy Description": "This policy identifies Azure Application Gateways that do not have Web application firewall (WAF) enabled. As a best practice, enable WAF to manage and protect your web applications behind the Application Gateway from common exploits and vulnerabilities.",
    "Resource Type": "azurerm_application_gateway",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_gateway"
}

# PR-AZR-TRF-AGW-003

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
    "Policy Code": "PR-AZR-TRF-AGW-003",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Application Gateway is using Https protocol",
    "Policy Description": "Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.",
    "Resource Type": "azurerm_application_gateway",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_gateway"
}


# PR-AZR-TRF-AGW-004

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
    "Policy Code": "PR-AZR-TRF-AGW-004",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Application Gateway frontendIPConfigurations does not have public ip configured",
    "Policy Description": "Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.",
    "Resource Type": "azurerm_application_gateway",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_gateway"
}


# PR-AZR-TRF-AGW-005

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
    "Policy Code": "PR-AZR-TRF-AGW-005",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Application Gateway Backend is using Https protocol",
    "Policy Description": "Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.",
    "Resource Type": "azurerm_application_gateway",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_gateway"
}


# PR-AZR-TRF-AGW-006

default secret_certificate_is_in_keyvalut = null

azure_attribute_absence ["secret_certificate_is_in_keyvalut"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    not resource.properties.ssl_certificate
}  

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
    "Policy Code": "PR-AZR-TRF-AGW-006",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Application Gateway secret certificates stores in keyvault",
    "Policy Description": "This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert",
    "Resource Type": "azurerm_application_gateway",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_gateway"
}


# PR-AZR-TRF-AGW-007

default application_gateways_v2_waf_ruleset_OWASP_active = null

azure_attribute_absence ["application_gateways_v2_waf_ruleset_OWASP_active"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    not resource.properties.sku
}  

azure_attribute_absence ["application_gateways_v2_waf_ruleset_OWASP_active"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    sku := resource.properties.sku[_]
    not sku.name
}  

azure_attribute_absence ["application_gateways_v2_waf_ruleset_OWASP_active"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    sku := resource.properties.sku[_]
    not sku.tier
}  

azure_attribute_absence["application_gateways_v2_waf_ruleset_OWASP_active"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    not resource.properties.waf_configuration
}

azure_attribute_absence["application_gateways_v2_waf_ruleset_OWASP_active"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    waf_configuration := resource.properties.waf_configuration[_]
    not waf_configuration.enabled
}

azure_attribute_absence["application_gateways_v2_waf_ruleset_OWASP_active"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    waf_configuration := resource.properties.waf_configuration[_]
    not waf_configuration.rule_set_type
}

azure_attribute_absence["application_gateways_v2_waf_ruleset_OWASP_active"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    waf_configuration := resource.properties.waf_configuration[_]
    not waf_configuration.rule_set_version
}

azure_issue["application_gateways_v2_waf_ruleset_OWASP_active"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    sku := resource.properties.sku[_]
    not contains(lower(sku.name), "v2")
}

azure_issue["application_gateways_v2_waf_ruleset_OWASP_active"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    sku := resource.properties.sku[_]
    not contains(lower(sku.tier), "v2")
}

azure_issue["application_gateways_v2_waf_ruleset_OWASP_active"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    waf_configuration := resource.properties.waf_configuration[_]
    waf_configuration.enabled != true
}

azure_issue["application_gateways_v2_waf_ruleset_OWASP_active"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    waf_configuration := resource.properties.waf_configuration[_]
    lower(waf_configuration.rule_set_type) != "owasp"
}

azure_issue["application_gateways_v2_waf_ruleset_OWASP_active"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    waf_configuration := resource.properties.waf_configuration[_]
    # The above protection is also available on OWASP ModSecurity Core Rule Set (CRS) version 3.2 for preview version of Azure Application Gateway V2 along with 3.1
    to_number(waf_configuration.rule_set_version) < 3.1
}

application_gateways_v2_waf_ruleset_OWASP_active {
    lower(input.resources[_].type) == "azurerm_application_gateway"
    not azure_attribute_absence["application_gateways_v2_waf_ruleset_OWASP_active"]
    not azure_issue["application_gateways_v2_waf_ruleset_OWASP_active"]
}

application_gateways_v2_waf_ruleset_OWASP_active = false {
    azure_issue["application_gateways_v2_waf_ruleset_OWASP_active"]
}

application_gateways_v2_waf_ruleset_OWASP_active = false {
    azure_attribute_absence["application_gateways_v2_waf_ruleset_OWASP_active"]
} 

application_gateways_v2_waf_ruleset_OWASP_active_err = "Azure Application Gateway V2 currently does not have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1" {
    azure_issue["application_gateways_v2_waf_ruleset_OWASP_active"]
} else = "'azurerm_application_gateway' resource property 'name' and 'tier' under 'sku' block and 'enabled', 'rule_set_type' and 'rule_set_version' under 'waf_configuration' block need to be exist. one or all are missing." {
    azure_attribute_absence["application_gateways_v2_waf_ruleset_OWASP_active"]
}

application_gateways_v2_waf_ruleset_OWASP_active_metadata := {
    "Policy Code": "PR-AZR-TRF-AGW-007",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit",
    "Policy Description": "It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/",
    "Resource Type": "azurerm_application_gateway",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_gateway"
}
