package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2019-06-01-preview/servers/administrators

#
# PR-AZR-0085-ARM
#

default db_ad_admin = null

azure_attribute_absence["db_ad_admin"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/administrators"
    not resource.properties.administratorType
}

azure_attribute_absence["db_ad_admin"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/managedinstances/administrators"
    not resource.properties.administratorType
}

azure_issue["db_ad_admin"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/administrators"
    lower(resource.properties.administratorType) != "activedirectory"
}

azure_issue["db_ad_admin"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/managedinstances/administrators"
    lower(resource.properties.administratorType) != "activedirectory"
}

db_ad_admin {
    lower(input.resources[_].type) == "microsoft.sql/servers/administrators"
    not azure_issue["db_ad_admin"]
    not azure_attribute_absence["db_ad_admin"]
}

db_ad_admin {
    lower(input.resources[_].type) == "microsoft.sql/managedinstances/administrators"
    not azure_issue["db_ad_admin"]
    not azure_attribute_absence["db_ad_admin"]
}

db_ad_admin = false {
    azure_issue["db_ad_admin"]
}

db_ad_admin = false {
    azure_attribute_absence["db_ad_admin"]
}

db_ad_admin_err = "SQL servers which do not have Azure Active Directory admin configured" {
    azure_issue["db_ad_admin"]
}

db_ad_admin_miss_err = "DB administrators attribute administratorType missing in the resource" {
    azure_attribute_absence["db_ad_admin"]
}

db_ad_admin_metadata := {
    "Policy Code": "PR-AZR-0085-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "SQL servers which do not have Azure Active Directory admin configured",
    "Policy Description": "Checks to ensure that SQL servers are configured with Active Directory admin authentication. Azure Active Directory authentication is a mechanism of connecting to Microsoft Azure SQL Database and SQL Data Warehouse by using identities in Azure Active Directory (Azure AD). With Azure AD authentication, you can centrally manage the identities of database users and other Microsoft services in one central location.",
    "Compliance": ["CSA-CCM","ISO 27001","NIST 800","PCI-DSS"],
    "Resource Type": "microsoft.sql/servers/administrators",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2019-06-01-preview/servers/administrators"
}
