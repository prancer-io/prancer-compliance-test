package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/applicationgateways

#
# PR-AZR-AGW-001
#

default gw_tls = null

azure_attribute_absence["gw_tls"] {
    not input.properties.sslPolicy.minProtocolVersion
}

azure_issue["gw_tls"] {=
    lower(input.properties.sslPolicy.minProtocolVersion) != "tlsv1_2"
    lower(input.properties.sslPolicy.minProtocolVersion) != "tlsv1_3"
}

gw_tls {
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
} else = "App gateway attribute sslPolicy.minProtocolVersion is missing from the resource" {
    azure_attribute_absence["gw_tls"]
}

gw_tls_metadata := {
    "Policy Code": "PR-AZR-AGW-001",
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
# PR-AZR-AGW-002
#

default gw_waf = null

azure_attribute_absence["gw_waf"] {
    not input.properties.webApplicationFirewallConfiguration.enabled
}

azure_issue["gw_waf"] {
    input.properties.webApplicationFirewallConfiguration.enabled != true
}

gw_waf {
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
} else = "Azure Application Gateway attribute webApplicationFirewallConfiguration.enabled is missing from the resource" {
    azure_attribute_absence["gw_waf"]
}

gw_waf_metadata := {
    "Policy Code": "PR-AZR-AGW-002",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Application Gateway should have the Web application firewall (WAF) enabled",
    "Policy Description": "This policy identifies Azure Application Gateways that do not have Web application firewall (WAF) enabled. As a best practice, enable WAF to manage and protect your web applications behind the Application Gateway from common exploits and vulnerabilities.",
    "Resource Type": "microsoft.network/applicationgateways",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/applicationgateways"
}




# PR-AZR-AGW-003

default protocol = null

azure_attribute_absence ["protocol"] {
    httpListener := input.properties.httpListeners[_]
    not httpListener.properties.protocol
}  

azure_issue ["protocol"] {input
    httpListener := input.properties.httpListeners[_]
    lower(httpListener.properties.protocol) != "https"
} 

protocol {
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
    "Policy Code": "PR-AZR-AGW-003",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure Application Gateway is using Https protocol",
    "Policy Description": "Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.",
    "Resource Type": "microsoft.network/applicationgateways",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/applicationgateways"
}


# PR-AZR-AGW-004

default frontendPublicIPConfigurationsDisabled = null

azure_attribute_absence ["frontendPublicIPConfigurationsDisabled"] {
    frontendIPConfigurations := input.properties.frontendIPConfigurations[_]
    not frontendIPConfigurations.properties.publicIPAddress
}  

frontendPublicIPConfigurationsDisabled {
    azure_attribute_absence["frontendPublicIPConfigurationsDisabled"]
} 

frontendPublicIPConfigurationsDisabled = false {
    not azure_attribute_absence["frontendPublicIPConfigurationsDisabled"]
}

frontendPublicIPConfigurationsDisabled_err = "Application Gateway is currently allowing public ip address in frontend IP Configurations" {
    not azure_attribute_absence["frontendPublicIPConfigurationsDisabled"]
}

frontendPublicIPConfigurationsDisabled_metadata := {
    "Policy Code": "PR-AZR-AGW-004",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure Application Gateway frontendIPConfigurations does not have public ip configured",
    "Policy Description": "Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.",
    "Resource Type": "microsoft.network/applicationgateways",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/applicationgateways"
}


# PR-AZR-AGW-005

default backend_https_protocol_enabled = null

azure_attribute_absence ["backend_https_protocol_enabled"] {
    backendHttpSettingsCollection := input.properties.backendHttpSettingsCollection[_]
    not backendHttpSettingsCollection.properties.protocol
}  

azure_issue ["backend_https_protocol_enabled"] {
    backendHttpSettingsCollection := input.properties.backendHttpSettingsCollection[_]
    lower(backendHttpSettingsCollection.properties.protocol) != "https"
} 

backend_https_protocol_enabled {
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
    "Policy Code": "PR-AZR-AGW-005",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure Application Gateway Backend is using Https protocol",
    "Policy Description": "Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.",
    "Resource Type": "microsoft.network/applicationgateways",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/applicationgateways"
}


# PR-AZR-AGW-006

default secret_certificate_is_in_keyvalut = null

azure_attribute_absence ["secret_certificate_is_in_keyvalut"] {
    count(input.properties.sslCertificates) == 0
} 

azure_attribute_absence ["secret_certificate_is_in_keyvalut"] {
    sslCertificates := input.properties.sslCertificates[_]
    not sslCertificates.properties.keyVaultSecretId
}  

azure_issue ["secret_certificate_is_in_keyvalut"] {
    sslCertificates := input.properties.sslCertificates[_]
    trim(sslCertificates.properties.keyVaultSecretId, " ") == ""
}  

secret_certificate_is_in_keyvalut {
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
    "Policy Code": "PR-AZR-AGW-006",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure Application Gateway secret certificates stores in keyvault",
    "Policy Description": "This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert",
    "Resource Type": "microsoft.network/applicationgateways",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/applicationgateways"
}