package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/applicationgateways

#
# PR-AZR-CLD-AGW-001
#

default gw_tls = null

azure_attribute_absence["gw_tls"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    not resource.properties.sslPolicy.minProtocolVersion
}


source_path[{"gw_tls":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.network/applicationgateways"
    not resource.properties.sslPolicy.minProtocolVersion
    metadata:= {
        "resource_path": [["resources",i,"properties","sslPolicy","minProtocolVersion"]]
    }
}


azure_issue["gw_tls"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    lower(resource.properties.sslPolicy.minProtocolVersion) != "tlsv1_2"
    lower(resource.properties.sslPolicy.minProtocolVersion) != "tlsv1_3"
}

source_path[{"gw_tls":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.network/applicationgateways"
    lower(resource.properties.sslPolicy.minProtocolVersion) != "tlsv1_2"
    lower(resource.properties.sslPolicy.minProtocolVersion) != "tlsv1_3"
    metadata:= {
        "resource_path": [["resources",i,"properties","sslPolicy","minProtocolVersion"]]
    }
}

gw_tls {
    lower(input.resources[_].type) == "microsoft.network/applicationgateways"
    not azure_attribute_absence["gw_tls"]
    not azure_issue["gw_tls"]
}

gw_tls = false {
    azure_issue["gw_tls"]
}

gw_tls = false {
    azure_attribute_absence["gw_tls"]
}

gw_tls_err = "Azure Application Gateway currently allowing TLSv1.1 or lower" {
    azure_issue["gw_tls"]
}

gw_tls_miss_err = "App gateway attribute sslPolicy.minProtocolVersion is missing from the resource" {
    azure_attribute_absence["gw_tls"]
}

gw_tls_metadata := {
    "Policy Code": "PR-AZR-CLD-AGW-001",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Application Gateway should not allow TLSv1.1 or lower",
    "Policy Description": "The Application Gateway supports end-to-end SSL encryption using multiple TLS versions and by default, it supports TLS version 1.0 as the minimum version.<br><br>This policy identifies the Application Gateway instances that are configured to use TLS versions 1.1 or lower as the minimum protocol version. As a best practice set the MinProtocolVersion to TLSv1.2 (if you use custom SSL policy) or use the predefined â€˜AppGwSslPolicy20170401Sâ€™ policy.",
    "Resource Type": "microsoft.network/applicationgateways",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/applicationgateways"
}

#
# PR-AZR-CLD-AGW-002
#

default gw_waf = null

azure_attribute_absence["gw_waf"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    not resource.properties.webApplicationFirewallConfiguration.enabled
}

source_path[{"gw_waf":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.network/applicationgateways"
    not resource.properties.webApplicationFirewallConfiguration.enabled
    metadata:= {
        "resource_path": [["resources",i,"properties","webApplicationFirewallConfiguration","enabled"]]
    }
}

azure_issue["gw_waf"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    resource.properties.webApplicationFirewallConfiguration.enabled != true
}

source_path[{"gw_waf":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.network/applicationgateways"
    resource.properties.webApplicationFirewallConfiguration.enabled != true
    metadata:= {
        "resource_path": [["resources",i,"properties","webApplicationFirewallConfiguration","enabled"]]
    }
}

gw_waf {
    lower(input.resources[_].type) == "microsoft.network/applicationgateways"
    not azure_attribute_absence["gw_waf"]
    not azure_issue["gw_waf"]
}

gw_waf = false {
    azure_issue["gw_waf"]
}

gw_waf = false {
    azure_attribute_absence["gw_waf"]
}

gw_waf_err = "Azure Application Gateway currently does not have the Web application firewall (WAF) enabled" {
    azure_issue["gw_waf"]
}

gw_waf_miss_err = "Azure Application Gateway attribute webApplicationFirewallConfiguration.enabled is missing from the resource" {
    azure_attribute_absence["gw_waf"]
}

gw_waf_metadata := {
    "Policy Code": "PR-AZR-CLD-AGW-002",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Application Gateway should have the Web application firewall (WAF) enabled",
    "Policy Description": "This policy identifies Azure Application Gateways that do not have Web application firewall (WAF) enabled. As a best practice, enable WAF to manage and protect your web applications behind the Application Gateway from common exploits and vulnerabilities.",
    "Resource Type": "microsoft.network/applicationgateways",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/applicationgateways"
}




# PR-AZR-CLD-AGW-003

default protocol = null
azure_attribute_absence ["protocol"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    httpListener := resource.properties.httpListeners[_]
    not httpListener.properties.protocol
}  

source_path[{"protocol":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.network/applicationgateways"
    httpListener := resource.properties.httpListeners[j]
    not httpListener.properties.protocol
    metadata:= {
        "resource_path": [["resources",i,"properties","httpListeners",j,"properties","protocol"]]
    }
}

azure_issue ["protocol"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    httpListener := resource.properties.httpListeners[_]
    lower(httpListener.properties.protocol) != "https"
} 

source_path[{"protocol":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.network/applicationgateways"
    httpListener := resource.properties.httpListeners[j]
    lower(httpListener.properties.protocol) != "https"
    metadata:= {
        "resource_path": [["resources",i,"properties","httpListeners",j,"properties","protocol"]]
    }
}

protocol {
    lower(input.resources[_].type) == "microsoft.network/applicationgateways"
    not azure_attribute_absence["protocol"]
    not azure_issue["protocol"]
}

protocol = false {
    azure_issue["protocol"]
}

protocol = false {
    azure_attribute_absence["protocol"]
}

protocol_err = "'httpListeners' property 'protocol' is missing from 'microsoft.network/applicationgateways' resource" {
    azure_attribute_absence["protocol"]
} else = "Application Gateway is currently not using Https protocol" {
    azure_issue["protocol"]
}

protocol_metadata := {
    "Policy Code": "PR-AZR-CLD-AGW-003",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure Application Gateway is using Https protocol",
    "Policy Description": "Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.",
    "Resource Type": "microsoft.network/applicationgateways",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/applicationgateways"
}


# PR-AZR-CLD-AGW-004

default frontendPublicIPConfigurationsDisabled = null
azure_attribute_absence ["frontendPublicIPConfigurationsDisabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    frontendIPConfigurations := resource.properties.frontendIPConfigurations[_]
    not frontendIPConfigurations.properties.publicIPAddress
}  

frontendPublicIPConfigurationsDisabled {
    azure_attribute_absence["frontendPublicIPConfigurationsDisabled"]
} 

frontendPublicIPConfigurationsDisabled = false {
    lower(input.resources[_].type) == "microsoft.network/applicationgateways"
    not azure_attribute_absence["frontendPublicIPConfigurationsDisabled"]
}

frontendPublicIPConfigurationsDisabled_err = "Application Gateway is currently allowing public ip address in frontend IP Configurations" {
    lower(input.resources[_].type) == "microsoft.network/applicationgateways"
    not azure_attribute_absence["frontendPublicIPConfigurationsDisabled"]
}

frontendPublicIPConfigurationsDisabled_metadata := {
    "Policy Code": "PR-AZR-CLD-AGW-004",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure Application Gateway frontendIPConfigurations does not have public ip configured",
    "Policy Description": "Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.",
    "Resource Type": "microsoft.network/applicationgateways",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/applicationgateways"
}


# PR-AZR-CLD-AGW-005

default backend_https_protocol_enabled = null
azure_attribute_absence ["backend_https_protocol_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    backendHttpSettingsCollection := resource.properties.backendHttpSettingsCollection[_]
    not backendHttpSettingsCollection.properties.protocol
}  

azure_issue ["backend_https_protocol_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    backendHttpSettingsCollection := resource.properties.backendHttpSettingsCollection[_]
    lower(backendHttpSettingsCollection.properties.protocol) != "https"
} 

backend_https_protocol_enabled {
    lower(input.resources[_].type) == "microsoft.network/applicationgateways"
    not azure_attribute_absence["backend_https_protocol_enabled"]
    not azure_issue["backend_https_protocol_enabled"]
}

backend_https_protocol_enabled = false {
    azure_issue["backend_https_protocol_enabled"]
}

backend_https_protocol_enabled = false {
    azure_attribute_absence["backend_https_protocol_enabled"]
}

backend_https_protocol_enabled_err = "'backendHttpSettingsCollection' property 'protocol' is missing from 'microsoft.network/applicationgateways' resource" {
    azure_attribute_absence["backend_https_protocol_enabled"]
} else = "Application Gateway backend is currently not using Https protocol" {
    azure_issue["backend_https_protocol_enabled"]
}

backend_https_protocol_enabled_metadata := {
    "Policy Code": "PR-AZR-CLD-AGW-005",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure Application Gateway Backend is using Https protocol",
    "Policy Description": "Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.",
    "Resource Type": "microsoft.network/applicationgateways",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/applicationgateways"
}


# PR-AZR-CLD-AGW-006

default secret_certificate_is_in_keyvalut = null

azure_attribute_absence ["secret_certificate_is_in_keyvalut"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    count(resource.properties.sslCertificates) == 0
} 

azure_attribute_absence ["secret_certificate_is_in_keyvalut"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    sslCertificates := resource.properties.sslCertificates[_]
    not sslCertificates.properties.keyVaultSecretId
}  

azure_issue ["secret_certificate_is_in_keyvalut"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    sslCertificates := resource.properties.sslCertificates[_]
    trim(sslCertificates.properties.keyVaultSecretId, " ") == ""
}  

secret_certificate_is_in_keyvalut {
   lower(input.resources[_].type) == "microsoft.network/applicationgateways"
   not azure_attribute_absence["secret_certificate_is_in_keyvalut"]
   not azure_issue["secret_certificate_is_in_keyvalut"]
}

secret_certificate_is_in_keyvalut = false {
    azure_attribute_absence["secret_certificate_is_in_keyvalut"]
}

secret_certificate_is_in_keyvalut = false {
    azure_issue["secret_certificate_is_in_keyvalut"]
}

secret_certificate_is_in_keyvalut_err = "'sslCertificates' property 'keyVaultSecretId' is missing from 'microsoft.network/applicationgateways' resource" {
    azure_attribute_absence["secret_certificate_is_in_keyvalut"]
} else = "Application Gateway is currently not storing ssl certificates in keyvalut"{
	azure_issue["secret_certificate_is_in_keyvalut"]
}

secret_certificate_is_in_keyvalut_metadata := {
    "Policy Code": "PR-AZR-CLD-AGW-006",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure Application Gateway secret certificates stores in keyvault",
    "Policy Description": "This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert",
    "Resource Type": "microsoft.network/applicationgateways",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/applicationgateways"
}


#
# PR-AZR-CLD-AGW-007
#

default application_gateways_v2_waf_ruleset_OWASP_active = null

azure_attribute_absence["application_gateways_v2_waf_ruleset_OWASP_active"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    not resource.properties.sku.name
}

azure_attribute_absence["application_gateways_v2_waf_ruleset_OWASP_active"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    not resource.properties.sku.tier
}

azure_attribute_absence["application_gateways_v2_waf_ruleset_OWASP_active"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    not resource.properties.webApplicationFirewallConfiguration.enabled
}

azure_attribute_absence["application_gateways_v2_waf_ruleset_OWASP_active"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    not resource.properties.webApplicationFirewallConfiguration.ruleSetType
}

azure_attribute_absence["application_gateways_v2_waf_ruleset_OWASP_active"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    not resource.properties.webApplicationFirewallConfiguration.ruleSetVersion
}

azure_issue["application_gateways_v2_waf_ruleset_OWASP_active"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    not contains(lower(resource.properties.sku.name), "v2")
}

azure_issue["application_gateways_v2_waf_ruleset_OWASP_active"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    not contains(lower(resource.properties.sku.tier), "v2")
}

azure_issue["application_gateways_v2_waf_ruleset_OWASP_active"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    resource.properties.webApplicationFirewallConfiguration.enabled != true
}

azure_issue["application_gateways_v2_waf_ruleset_OWASP_active"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    lower(resource.properties.webApplicationFirewallConfiguration.ruleSetType) != "owasp"
}

azure_issue["application_gateways_v2_waf_ruleset_OWASP_active"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    # The above protection is also available on OWASP ModSecurity Core Rule Set (CRS) version 3.2 for preview version of Azure Application Gateway V2 along with 3.1
    to_number(resource.properties.webApplicationFirewallConfiguration.ruleSetVersion) < 3.1
}

application_gateways_v2_waf_ruleset_OWASP_active {
    lower(input.resources[_].type) == "microsoft.network/applicationgateways"
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
} else = "'microsoft.network/applicationgateways' resource property 'name' and 'tier' under 'sku' block and 'enabled', 'ruleSetType' and 'ruleSetVersion' under 'webApplicationFirewallConfiguration' block need to be exist. one or all are missing." {
    azure_attribute_absence["application_gateways_v2_waf_ruleset_OWASP_active"]
}

application_gateways_v2_waf_ruleset_OWASP_active_metadata := {
    "Policy Code": "PR-AZR-CLD-AGW-007",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit",
    "Policy Description": "It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/",
    "Resource Type": "microsoft.network/applicationgateways",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/applicationgateways"
}