#
# PR-AZR-0085
#

package rule
default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2019-06-01-preview/servers/administrators

rulepass {
    lower(input.type) == "microsoft.sql/servers/administrators"
    input.properties.administratorType == "ActiveDirectory"
}

rulepass {
    lower(input.type) == "microsoft.sql/managedinstances/administrators"
    input.properties.administratorType == "ActiveDirectory"
}

metadata := {
    "Policy Code": "PR-AZR-0085",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "SQL servers which do not have Azure Active Directory admin configured",
    "Policy Description": "Checks to ensure that SQL servers are configured with Active Directory admin authentication. Azure Active Directory authentication is a mechanism of connecting to Microsoft Azure SQL Database and SQL Data Warehouse by using identities in Azure Active Directory (Azure AD). With Azure AD authentication, you can centrally manage the identities of database users and other Microsoft services in one central location.",
    "Resource Type": "microsoft.sql/servers/administrators",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2019-06-01-preview/servers/administrators"
}
