package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

array_contains(array_property, element) = true {
  lower(array_property[_]) == element
} else = false { true }

# https://docs.microsoft.com/en-us/azure/templates/azurerm_storage_account
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account
#
# PR-AZR-TRF-STR-003
#

default storage_secure = null

azure_attribute_absence["storage_secure"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    # Defaults to true if property not available
    #not resource.properties.enable_https_traffic_only
    not has_property(resource.properties, "enable_https_traffic_only")
}

azure_issue["storage_secure"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    resource.properties.enable_https_traffic_only != true
}

storage_secure {
    lower(input.resources[_].type) == "azurerm_storage_account"
    not azure_attribute_absence["storage_secure"]
    not azure_issue["storage_secure"]
}

storage_secure {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_attribute_absence["storage_secure"]
    not azure_issue["storage_secure"]
}

storage_secure = false {
    azure_issue["storage_secure"]
}

storage_secure_err = "Storage Accounts https based secure transfer is not enabled" {
    azure_issue["storage_secure"]
}

storage_secure_metadata := {
    "Policy Code": "PR-AZR-TRF-STR-003",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Storage Accounts https based secure transfer should be enabled",
    "Policy Description": "The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesnâ€™t support HTTPs for custom domain names, this option is not applied when using a custom domain name.",
    "Resource Type": "azurerm_storage_account",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account"
}


#
# PR-AZR-TRF-STR-004
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account_network_rules

default storage_acl = null

azure_attribute_absence ["storage_acl"] {
    count([c | input.resources[_].type == "azurerm_storage_account_network_rules"; c := 1]) == 0
}

azure_attribute_absence["storage_acl"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account_network_rules"
    not resource.properties.default_action
}

azure_issue["storage_acl"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    count([c | r := input.resources[_];
              r.type == "azurerm_storage_account_network_rules";
              contains(r.properties.storage_account_name, resource.properties.compiletime_identity);
              lower(r.properties.default_action) == "deny";
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_storage_account_network_rules";
              contains(r.properties.storage_account_name, concat(".", [resource.type, resource.name]));
              lower(r.properties.default_action) == "deny";
              c := 1]) == 0
}

# azure_issue["storage_acl"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_storage_account_network_rules"
#     lower(resource.properties.default_action) != "deny"
# }

azure_inner_attribute_absence["storage_acl"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    not resource.properties.network_rules
}

azure_inner_attribute_absence["storage_acl"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    network_rules := resource.properties.network_rules[_]
    not network_rules.default_action
}
azure_inner_issue["storage_acl"] {
    count([c | r := input.resources[_];
              r.type == "azurerm_storage_account";
              lower(r.properties.network_rules[_].default_action) == "deny";
              c := 1]) == 0
}

# azure_inner_attribute_absence["storage_acl"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_storage_account"
#     not resource.properties.network_rules
# }


# azure_inner_issue["storage_acl"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_storage_account"
#     network_rules := resource.properties.network_rules[_]
#     lower(network_rules.default_action) != "deny"
# }

storage_acl {
    lower(input.resources[_].type) == "azurerm_storage_account"
    not azure_attribute_absence["storage_acl"]
    not azure_issue["storage_acl"]
}

storage_acl {
    lower(input.resources[_].type) == "azurerm_storage_account"
    not azure_inner_attribute_absence["storage_acl"]
    not azure_inner_issue["storage_acl"]
}

storage_acl = false {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_attribute_absence["storage_acl"]
    azure_inner_attribute_absence["storage_acl"]
}

storage_acl = false {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_issue["storage_acl"]
    azure_inner_issue["storage_acl"]
}

# storage_acl = false {
#     lower(input.resources[_].type) == "azurerm_storage_account"
#     azure_inner_issue["storage_acl"]
# }

storage_acl_err = "azurerm_storage_account_network_rules property 'default_action' or azurerm_storage_account's inner block 'network_rules' with property 'default_action' need to be exist. Its missing from the resource. Please set the value to 'deny' after property addition." {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_attribute_absence["storage_acl"]
    azure_inner_attribute_absence["storage_acl"]
} else = "Storage Accounts firewall rule is currently not enabled" {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_issue["storage_acl"]
    azure_inner_issue["storage_acl"]
} 
# else = "Storage Accounts firewall rule is currently not enabled" {
#  	lower(input.resources[_].type) == "azurerm_storage_account"
#  	azure_inner_issue["storage_acl"]
# }

storage_acl_metadata := {
    "Policy Code": "PR-AZR-TRF-STR-004",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Storage Accounts should have firewall rules enabled",
    "Policy Description": "Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.",
    "Resource Type": "azurerm_storage_account",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account"
}

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/advanced_threat_protection
# Advanced Threat Protection should be enabled for storage account
# PR-AZR-TRF-STR-005

default storage_threat_protection = null

azure_attribute_absence["storage_threat_protection"] {
    count([c | input.resources[_].type == "azurerm_advanced_threat_protection"; c := 1]) == 0
}

azure_attribute_absence["storage_threat_protection"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_advanced_threat_protection"
    not resource.properties.enabled
}

azure_issue["storage_threat_protection"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    count([c | r := input.resources[_];
              r.type == "azurerm_advanced_threat_protection";
              contains(r.properties.target_resource_id, resource.properties.compiletime_identity);
              r.properties.enabled == true;
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_advanced_threat_protection";
              contains(r.properties.target_resource_id, concat(".", [resource.type, resource.name]));
              r.properties.enabled == true;
              c := 1]) == 0
}

# azure_issue["storage_threat_protection"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_advanced_threat_protection"
#     resource.properties.enabled == false
# }

storage_threat_protection {
    lower(input.resources[_].type) == "azurerm_storage_account"
    not azure_attribute_absence["storage_threat_protection"]
    not azure_issue["storage_threat_protection"]
}

storage_threat_protection = false {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_attribute_absence["storage_threat_protection"]
}

storage_threat_protection = false {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_issue["storage_threat_protection"]
}

storage_threat_protection_err = "azurerm_advanced_threat_protection property 'enabled' need to be exist. Its missing from the resource. Please set the value to 'true' after property addition." {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_attribute_absence["storage_threat_protection"]
} else = "Advanced Threat Protection is currently not enabled for storage account" {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_issue["storage_threat_protection"]
}

storage_threat_protection_metadata := {
    "Policy Code": "PR-AZR-TRF-STR-005",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Advanced Threat Protection should be enabled for storage account",
    "Policy Description": "Advanced Threat Protection should be enabled for all the storage accounts",
    "Resource Type": "azurerm_storage_account",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account"
}

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_encryption_scope
# PR-AZR-TRF-STR-008

default keySource = null

azure_attribute_absence["keySource"] {
    count([c | input.resources[_].type == "azurerm_storage_encryption_scope"; c := 1]) == 0
}

# azure_attribute_absence["keySource"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_storage_encryption_scope"
#     not resource.properties.source
# }

azure_issue["keySource"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    count([c | r := input.resources[_];
              r.type == "azurerm_storage_encryption_scope";
              contains(r.properties.storage_account_id, resource.properties.compiletime_identity);
              lower(r.properties.source) == "microsoft.keyvault";
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_storage_encryption_scope";
              contains(r.properties.storage_account_id, concat(".", [resource.type, resource.name]));
              lower(r.properties.source) == "microsoft.keyvault";
              c := 1]) == 0
}

# azure_issue["keySource"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_storage_encryption_scope"
#     lower(resource.properties.source) != "microsoft.keyvault"
# }

keySource {
    lower(input.resources[_].type) == "azurerm_storage_account"
    not azure_attribute_absence["keySource"]
    not azure_issue["keySource"]
}

keySource = false {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_issue["keySource"]
}

keySource = false {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_attribute_absence["keySource"]
}

keySource_err = "azurerm_storage_encryption_scope with its property 'source' need to be exist. Its missing from the resource. Please set the value to 'Microsoft.KeyVault' after property addition." {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_attribute_absence["keySource"]
} else = "Critical data storage in Storage Account is currently not encrypted with Customer Managed Key" {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_issue["keySource"] 
}

keySource_metadata := {
    "Policy Code": "PR-AZR-TRF-STR-008",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure critical data storage in Storage Account is encrypted with Customer Managed Key",
    "Policy Description": "By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.",
    "Resource Type": "azurerm_storage_account",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account
# PR-AZR-TRF-STR-009

default region = null

azure_attribute_absence["region"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    not resource.location
}

azure_issue["region"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    lower(resource.location) != "northeurope"
    lower(resource.location) != "westeurope"
}

region {
    lower(input.resources[_].type) == "azurerm_storage_account"
    not azure_attribute_absence["region"]
    not azure_issue["region"]
}

region = false {
    azure_attribute_absence["region"]
}

region = false {
    azure_issue["region"]
}

region_err = "azurerm_storage_account property 'location' need to be exist. Its missing from the resource." {
    azure_attribute_absence["region"]
} else = "Storage Accounts location configuration is currenly not inside of Europe" {
    azure_issue["region"] 
}

region_metadata := {
    "Policy Code": "PR-AZR-TRF-STR-009",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Storage Accounts location configuration should be inside of Europe",
    "Policy Description": "Identify Storage Accounts outside of the following regions: northeurope, westeurope",
    "Resource Type": "azurerm_storage_account",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account
# PR-AZR-TRF-STR-010

default storage_account_public_access_disabled = null

# defaults to false
azure_attribute_absence["storage_account_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    not resource.properties.allow_blob_public_access
}

azure_issue["storage_account_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    resource.properties.allow_blob_public_access == true
}

storage_account_public_access_disabled {
    lower(input.resources[_].type) == "azurerm_storage_account"
    not azure_attribute_absence["storage_account_public_access_disabled"]
    not azure_issue["storage_account_public_access_disabled"]
}

storage_account_public_access_disabled {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_attribute_absence["storage_account_public_access_disabled"]
    not azure_issue["storage_account_public_access_disabled"]
}

storage_account_public_access_disabled = false {
    azure_issue["storage_account_public_access_disabled"]
}

storage_account_public_access_disabled_err = "Storage Account currently allowing public access to all blobs or containers" {
    azure_issue["storage_secure"]
}

storage_account_public_access_disabled_metadata := {
    "Policy Code": "PR-AZR-TRF-STR-010",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that Storage Account should not allow public access to all blobs or containers",
    "Policy Description": "This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert",
    "Resource Type": "azurerm_storage_account",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account
#
# PR-AZR-TRF-STR-014
#

default storage_account_queue_logging_enabled_for_all_operation = null

azure_attribute_absence["storage_account_queue_logging_enabled_for_all_operation"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    not resource.properties.queue_properties
}

azure_attribute_absence["storage_account_queue_logging_enabled_for_all_operation"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    queue_properties := resource.properties.queue_properties[_]
    not queue_properties.logging
}

azure_issue["storage_account_queue_logging_enabled_for_all_operation"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    queue_properties := resource.properties.queue_properties[_]
    logging := queue_properties.logging[_]
    not logging.read
    not logging.write
    not logging.delete
}

storage_account_queue_logging_enabled_for_all_operation {
    lower(input.resources[_].type) == "azurerm_storage_account"
    count(input.resources[_].properties.queue_properties) > 0
    not azure_attribute_absence["storage_account_queue_logging_enabled_for_all_operation"]
    not azure_issue["storage_account_queue_logging_enabled_for_all_operation"]
}

storage_account_queue_logging_enabled_for_all_operation = false {
	lower(input.resources[_].type) == "azurerm_storage_account"
    count(input.resources[_].properties.queue_properties) > 0
    azure_attribute_absence["storage_account_queue_logging_enabled_for_all_operation"]
}

storage_account_queue_logging_enabled_for_all_operation = false {
	lower(input.resources[_].type) == "azurerm_storage_account"
    count(input.resources[_].properties.queue_properties) > 0
    azure_issue["storage_account_queue_logging_enabled_for_all_operation"]
}

storage_account_queue_logging_enabled_for_all_operation_err = "azurerm_storage_account property block 'queue_properties.logging' need to be exist with child property 'read', 'write' and 'delete'. one or all are missing from the resource." {
    lower(input.resources[_].type) == "azurerm_storage_account"
    count(input.resources[_].properties.queue_properties) > 0
    azure_attribute_absence["storage_account_queue_logging_enabled_for_all_operation"]
} else = "Storage Accounts queue service logging is currently not enabled" {
	lower(input.resources[_].type) == "azurerm_storage_account"
    count(input.resources[_].properties.queue_properties) > 0
    azure_issue["storage_account_queue_logging_enabled_for_all_operation"]
}

storage_account_queue_logging_enabled_for_all_operation_metadata := {
    "Policy Code": "PR-AZR-TRF-STR-014",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Storage Accounts queue service logging should be enabled",
    "Policy Description": "The Azure Storage Queue service logging records details for both successful and failed requests made to the queues, as well as end-to-end latency, server latency, and authentication information.",
    "Resource Type": "azurerm_storage_account",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account"
}

#
# PR-AZR-TRF-STR-011
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account_network_rules

default storage_nr_allow_trusted_azure_services = null

azure_attribute_absence ["storage_nr_allow_trusted_azure_services"] {
   count([c | input.resources[_].type == "azurerm_storage_account_network_rules"; c := 1]) == 0
}

azure_attribute_absence["storage_nr_allow_trusted_azure_services"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account_network_rules"
    not resource.properties.bypass
}

azure_issue["storage_nr_allow_trusted_azure_services"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    count([c | r := input.resources[_];
              r.type == "azurerm_storage_account_network_rules";
              contains(r.properties.storage_account_name, resource.properties.compiletime_identity);
              array_contains(r.properties.bypass, "azureservices");
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_storage_account_network_rules";
              contains(r.properties.storage_account_name, concat(".", [resource.type, resource.name]));
              array_contains(r.properties.bypass, "azureservices");
              c := 1]) == 0
}

# azure_issue["storage_nr_allow_trusted_azure_services"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_storage_account_network_rules"
#     #lower(resource.properties.bypass[_]) != "azureservices"
#     count([c | lower(resource.properties.bypass[_]) == "azureservices"; c := 1]) == 0
# }

azure_inner_attribute_absence["storage_nr_allow_trusted_azure_services"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    not resource.properties.network_rules
}

azure_inner_attribute_absence["storage_nr_allow_trusted_azure_services"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    network_rules := resource.properties.network_rules[_]
    not network_rules.bypass
}

azure_inner_issue["storage_nr_allow_trusted_azure_services"] {
    count([c | r := input.resources[_];
              r.type == "azurerm_storage_account";
              array_contains(r.properties.network_rules[_].bypass, "azureservices");
              #count([ci | lower(r.properties.network_rules[_].bypass[_]) == "azureservices"; c := 1]) > 0;
              c := 1]) == 0
}

# azure_inner_issue["storage_nr_allow_trusted_azure_services"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_storage_account"
#     network_rules := resource.properties.network_rules[_]
#     not contains(network_rules.bypass, "azureservices")
# }

storage_nr_allow_trusted_azure_services {
    lower(input.resources[_].type) == "azurerm_storage_account"
    not azure_attribute_absence["storage_nr_allow_trusted_azure_services"]
    not azure_issue["storage_nr_allow_trusted_azure_services"]
}

storage_nr_allow_trusted_azure_services {
    lower(input.resources[_].type) == "azurerm_storage_account"
    not azure_inner_attribute_absence["storage_nr_allow_trusted_azure_services"]
    not azure_inner_issue["storage_nr_allow_trusted_azure_services"]
}

storage_nr_allow_trusted_azure_services = false {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_attribute_absence["storage_nr_allow_trusted_azure_services"]
    azure_inner_attribute_absence["storage_nr_allow_trusted_azure_services"]
}

storage_nr_allow_trusted_azure_services = false {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_issue["storage_nr_allow_trusted_azure_services"]
    azure_inner_issue["storage_nr_allow_trusted_azure_services"]
}

# storage_nr_allow_trusted_azure_services = false {
#     lower(input.resources[_].type) == "azurerm_storage_account"
#     azure_inner_issue["storage_nr_allow_trusted_azure_services"]
# }

storage_nr_allow_trusted_azure_services_err = "azurerm_storage_account_network_rules property 'bypass' or azurerm_storage_account's inner block 'network_rules' with property 'bypass' need to be exist. Its missing from the resource. Please add 'AzureServices' in the array element after property addition." {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_attribute_absence["storage_nr_allow_trusted_azure_services"]
    azure_inner_attribute_absence["storage_nr_allow_trusted_azure_services"]
} else = "Storage Accounts is not currently allowing trusted Microsoft services" {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_issue["storage_nr_allow_trusted_azure_services"]
    azure_inner_issue["storage_nr_allow_trusted_azure_services"]
} 
# else = "Storage Accounts is not currently allowing trusted Microsoft services" {
#     lower(input.resources[_].type) == "azurerm_storage_account"
#     azure_inner_issue["storage_nr_allow_trusted_azure_services"]
# }

storage_nr_allow_trusted_azure_services_metadata := {
    "Policy Code": "PR-AZR-TRF-STR-011",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Storage Accounts access should be allowed for trusted Microsoft services",
    "Policy Description": "Ensure that 'Allow trusted Microsoft services to access this storage account' exception is enabled within your Azure Storage account configuration settings to grant access to trusted cloud services.",
    "Resource Type": "azurerm_storage_account",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account_network_rules"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account
#

# PR-AZR-TRF-STR-017
# As per Farshid: For the storage naming convention we have to make sure the name is not the variable name
# If a variable name is in the name , and there is no value for that, just pass the test Var.
default storage_correct_naming_convention = null

is_name_contains_variable_reference["storage_correct_naming_convention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    contains(resource.properties.name, "${")
}

azure_attribute_absence["storage_correct_naming_convention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    not resource.properties.name
}

azure_issue["storage_correct_naming_convention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    not regex.match("^[a-z0-9]{3,24}$",
        resource.properties.name)
}

storage_correct_naming_convention {
    lower(input.resources[_].type) == "azurerm_storage_account"
    is_name_contains_variable_reference["storage_correct_naming_convention"]
}

storage_correct_naming_convention {
    lower(input.resources[_].type) == "azurerm_storage_account"
    not azure_attribute_absence["storage_correct_naming_convention"]
    not azure_issue["storage_correct_naming_convention"]
}

storage_correct_naming_convention = false {
    azure_attribute_absence["storage_correct_naming_convention"]
}

storage_correct_naming_convention = false {
    azure_issue["storage_correct_naming_convention"]
    not is_name_contains_variable_reference["storage_correct_naming_convention"]
}

storage_correct_naming_convention_err = "azurerm_storage_account property 'name' need to be exist. Its missing from the resource." {
    azure_attribute_absence["storage_correct_naming_convention"]
} else = "Storage Account naming convention is not correct" {
    azure_issue["storage_correct_naming_convention"]
    not is_name_contains_variable_reference["storage_correct_naming_convention"]
}

storage_correct_naming_convention_metadata := {
    "Policy Code": "PR-AZR-TRF-STR-017",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Storage Account naming rules are correct",
    "Policy Description": "Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.",
    "Resource Type": "azurerm_storage_account",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account
# PR-AZR-TRF-STR-018
#

default storage_account_latest_tls_configured = null

#default to TLS1_0
azure_attribute_absence["storage_account_latest_tls_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    not resource.properties.min_tls_version
}

azure_issue["storage_account_latest_tls_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    lower(resource.properties.min_tls_version) != "tls1_2"
}

storage_account_latest_tls_configured {
    lower(input.resources[_].type) == "azurerm_storage_account"
    not azure_attribute_absence["storage_account_latest_tls_configured"]
    not azure_issue["storage_account_latest_tls_configured"]
}

storage_account_latest_tls_configured = false {
    azure_attribute_absence["storage_account_latest_tls_configured"]
}

storage_account_latest_tls_configured = false {
    azure_issue["storage_account_latest_tls_configured"]
}

storage_account_latest_tls_configured_err = "azurerm_storage_account property 'min_tls_version' need to be exist. Its missing from the resource. Please set the value to 'TLS1_2' after property addition." {
    azure_attribute_absence["storage_account_latest_tls_configured"]
} else = "Azure Storage Account currently dont have latest version of tls configured" {
    azure_issue["storage_account_latest_tls_configured"]
}

storage_account_latest_tls_configured_metadata := {
    "Policy Code": "PR-AZR-TRF-STR-018",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Azure Storage Account has latest version of tls configured",
    "Policy Description": "This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert",
    "Resource Type": "azurerm_storage_account",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account"
}


# PR-AZR-TRF-STR-019

default storage_account_uses_privatelink = null

azure_attribute_absence ["storage_account_uses_privatelink"] {
    count([c | input.resources[_].type == "azurerm_private_endpoint"; c := 1]) == 0
}

azure_issue ["storage_account_uses_privatelink"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
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

storage_account_uses_privatelink = false {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_attribute_absence["storage_account_uses_privatelink"]
}

storage_account_uses_privatelink {
    lower(input.resources[_].type) == "azurerm_storage_account"
    not azure_attribute_absence["storage_account_uses_privatelink"]
    not azure_issue["storage_account_uses_privatelink"]
}

storage_account_uses_privatelink = false {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_issue["storage_account_uses_privatelink"]
}

storage_account_uses_privatelink_err = "azurerm_storage_account should have link with azurerm_private_endpoint and azurerm_private_endpoint's private_service_connection either need to have 'private_connection_resource_id' or 'private_connection_resource_alias' property. Seems there is no link established or mentioed properties are missing." {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_attribute_absence["storage_account_uses_privatelink"]
} else = "Azure Storage account currently not using private link" {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_issue["storage_account_uses_privatelink"]
}

storage_account_uses_privatelink_metadata := {
    "Policy Code": "PR-AZR-TRF-STR-019",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Storage account should use private link",
    "Policy Description": "Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.",
    "Resource Type": "azurerm_storage_account",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account"
}


# PR-AZR-TRF-STR-020

default storage_account_uses_double_encryption = null

azure_attribute_absence["storage_account_uses_double_encryption"] {
    count([c | input.resources[_].type == "azurerm_storage_encryption_scope"; c := 1]) == 0
}

azure_issue["storage_account_uses_double_encryption"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    count([c | r := input.resources[_];
              r.type == "azurerm_storage_encryption_scope";
              contains(r.properties.storage_account_id, resource.properties.compiletime_identity);
              r.properties.infrastructure_encryption_required == true;
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_storage_encryption_scope";
              contains(r.properties.storage_account_id, concat(".", [resource.type, resource.name]));
              r.properties.infrastructure_encryption_required == true;
              c := 1]) == 0
}

storage_account_uses_double_encryption {
    lower(input.resources[_].type) == "azurerm_storage_account"
    not azure_attribute_absence["storage_account_uses_double_encryption"]
    not azure_issue["storage_account_uses_double_encryption"]
}

storage_account_uses_double_encryption = false {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_issue["storage_account_uses_double_encryption"]
}

storage_account_uses_double_encryption = false {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_attribute_absence["storage_account_uses_double_encryption"]
}

storage_account_uses_double_encryption_err = "azurerm_storage_encryption_scope with its property 'infrastructure_encryption_required' need to be exist. Its missing from the resource. Please set the value to 'true' after property addition." {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_attribute_absence["storage_account_uses_double_encryption"]
} else = "Storage account encryption scopes currently not using double encryptiony" {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_issue["storage_account_uses_double_encryption"] 
}

storage_account_uses_double_encryption_metadata := {
    "Policy Code": "PR-AZR-TRF-STR-020",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Storage account encryption scopes should use double encryption for data at rest",
    "Policy Description": "Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.",
    "Resource Type": "azurerm_storage_account",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account"
}


#
# PR-AZR-TRF-STR-024
#

default storage_shared_access_key_disabled = null
# Defaults to true if property not available
azure_attribute_absence["storage_shared_access_key_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    not has_property(resource.properties, "shared_access_key_enabled")
}

azure_issue["storage_shared_access_key_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    resource.properties.shared_access_key_enabled != false
}

storage_shared_access_key_disabled {
    lower(input.resources[_].type) == "azurerm_storage_account"
    not azure_attribute_absence["storage_shared_access_key_disabled"]
    not azure_issue["storage_shared_access_key_disabled"]
}

storage_shared_access_key_disabled = false {
    azure_attribute_absence["storage_shared_access_key_disabled"]
}

storage_shared_access_key_disabled = false {
    azure_issue["storage_shared_access_key_disabled"]
}

storage_shared_access_key_disabled_err = "azurerm_storage_account property 'shared_access_key_enabled' is missing from the resource" {
    azure_attribute_absence["storage_shared_access_key_disabled"]
} else = "Storage Accounts is currently not preventing shared key access" {
    azure_issue["storage_shared_access_key_disabled"]
}

storage_shared_access_key_disabled_metadata := {
    "Policy Code": "PR-AZR-TRF-STR-024",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Storage accounts should prevent shared key access",
    "Policy Description": "Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.",
    "Resource Type": "azurerm_storage_account",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account"
}


#
# PR-AZR-TRF-STR-023
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account_network_rules

default storage_acl_usage_vnet = null

azure_attribute_absence ["storage_acl_usage_vnet"] {
    count([c | input.resources[_].type == "azurerm_storage_account_network_rules"; c := 1]) == 0
}

azure_issue["storage_acl_usage_vnet"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    count([c | r := input.resources[_];
              r.type == "azurerm_storage_account_network_rules";
              contains(r.properties.storage_account_name, resource.properties.compiletime_identity);
              lower(r.properties.default_action) == "deny";
              count(r.properties.virtual_network_subnet_ids) > 0;
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_storage_account_network_rules";
              contains(r.properties.storage_account_name, concat(".", [resource.type, resource.name]));
              lower(r.properties.default_action) == "deny";
              count(r.properties.virtual_network_subnet_ids) > 0;
              c := 1]) == 0
}

azure_inner_attribute_absence["storage_acl_usage_vnet"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    not resource.properties.network_rules
}

azure_inner_issue["storage_acl_usage_vnet"] {
    count([c | r := input.resources[_];
              r.type == "azurerm_storage_account";
              lower(r.properties.network_rules[_].default_action) == "deny";
              count(r.properties.network_rules[_].virtual_network_subnet_ids) > 0;
              c := 1]) == 0
}

storage_acl_usage_vnet {
    lower(input.resources[_].type) == "azurerm_storage_account"
    not azure_attribute_absence["storage_acl_usage_vnet"]
    not azure_issue["storage_acl_usage_vnet"]
}

storage_acl_usage_vnet {
    lower(input.resources[_].type) == "azurerm_storage_account"
    not azure_inner_attribute_absence["storage_acl_usage_vnet"]
    not azure_inner_issue["storage_acl_usage_vnet"]
}

storage_acl_usage_vnet = false {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_attribute_absence["storage_acl_usage_vnet"]
    azure_inner_attribute_absence["storage_acl_usage_vnet"]
}

storage_acl_usage_vnet = false {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_issue["storage_acl_usage_vnet"]
    azure_inner_issue["storage_acl_usage_vnet"]
}

storage_acl_usage_vnet_err = "azurerm_storage_account_network_rules property 'default_action' and 'virtual_network_subnet_ids' or azurerm_storage_account's inner block 'network_rules' with property 'default_action' and 'virtual_network_subnet_ids' need to be exist. Its missing from the resource." {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_attribute_absence["storage_acl_usage_vnet"]
    azure_inner_attribute_absence["storage_acl_usage_vnet"]
} else = "Storage Accounts currently not using virtual network service endpoint" {
    lower(input.resources[_].type) == "azurerm_storage_account"
    azure_issue["storage_acl_usage_vnet"]
    azure_inner_issue["storage_acl_usage_vnet"]
}

storage_acl_usage_vnet_metadata := {
    "Policy Code": "PR-AZR-TRF-STR-023",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Storage Accounts should use a virtual network service endpoint",
    "Policy Description": "This policy audits any Storage Account not configured to use a virtual network service endpoint.",
    "Resource Type": "azurerm_storage_account",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account_network_rules"
}


#
# PR-AZR-TRF-STR-025
#

default storage_account_file_share_usage_smb_protocol = null

azure_attribute_absence["storage_account_file_share_usage_smb_protocol"] {
    resource := input.resources[_]
    resource.type == "azurerm_storage_share"
    not has_property(resource.properties, "enabled_protocol")
}

azure_issue["storage_account_file_share_usage_smb_protocol"] {
    resource := input.resources[_]
    resource.type == "azurerm_storage_share"
    lower(resource.properties.enabled_protocol) != "smb"
}

storage_account_file_share_usage_smb_protocol {
    input.resources[_].type == "azurerm_storage_share"
    not azure_attribute_absence["storage_account_file_share_usage_smb_protocol"]
    not azure_issue["storage_account_file_share_usage_smb_protocol"]
}

storage_account_file_share_usage_smb_protocol = false {
    azure_issue["storage_account_file_share_usage_smb_protocol"]
}

storage_account_file_share_usage_smb_protocol {
    azure_attribute_absence["storage_account_file_share_usage_smb_protocol"]
    not azure_issue["storage_account_file_share_usage_smb_protocol"]
}

storage_account_file_share_usage_smb_protocol_err = "Storage accounts File Share currently not using SMB protocol" {
    azure_issue["storage_account_file_share_usage_smb_protocol"]
}

storage_account_file_share_usage_smb_protocol_metadata := {
    "Policy Code": "PR-AZR-TRF-STR-025",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Storage Account File Share should use SMB protocol",
    "Policy Description": "The Server Message Block (SMB) protocol is a network file sharing protocol that allows applications on a computer to read and write to files and to request services from server programs in a computer network. The SMB protocol can be used on top of its TCP/IP protocol or other network protocols.",
    "Resource Type": "azurerm_storage_share",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_share"
}

