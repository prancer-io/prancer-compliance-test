package rule

# https://github.com/Azure/azure-service-operator/blob/master/config/samples/azure_v1alpha1_mysqlserveradministrator.yaml

#
# PR-AZR-0085-ASO
#

default db_ad_admin = null

azure_issue["db_ad_admin"] {
    lower(input.kind) == "mysqlserveradministrator"
    not resource.spec.administratorType
}

azure_issue["db_ad_admin"] {
    lower(input.kind) == "mysqlserveradministrator"
    lower(resource.properties.administratorType) != "activedirectory"
}

db_ad_admin {
    lower(input.kind) == "mysqlserveradministrator"
    not azure_issue["db_ad_admin"]
}

db_ad_admin = false {
    azure_issue["db_ad_admin"]
}

db_ad_admin_err = "SQL servers which do not have Azure Active Directory admin configured" {
    azure_issue["db_ad_admin"]
}

db_ad_admin_metadata := {
    "Policy Code": "PR-AZR-0085-ASO",
    "Type": "IaC",
    "Product": "ASO",
    "Language": "ASO template",
    "Policy Title": "SQL servers which do not have Azure Active Directory admin configured",
    "Policy Description": "Checks to ensure that SQL servers are configured with Active Directory admin authentication. Azure Active Directory authentication is a mechanism of connecting to Microsoft Azure SQL Database and SQL Data Warehouse by using identities in Azure Active Directory (Azure AD). With Azure AD authentication, you can centrally manage the identities of database users and other Microsoft services in one central location.",
    "Resource Type": "MySQLServerAdministrator",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/Azure/azure-service-operator/blob/master/config/samples/azure_v1alpha1_mysqlserveradministrator.yaml"
}
