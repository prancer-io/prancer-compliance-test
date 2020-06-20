package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2019-06-01-preview/servers/administrators

#
# SQL servers which do not have Azure Active Directory admin configured (294)
#

default db_ad_admin = null

db_ad_admin {
    lower(input.type) == "microsoft.sql/servers/administrators"
    lower(input.properties.administratorType) == "activedirectory"
}

db_ad_admin = false {
    lower(input.type) == "microsoft.sql/servers/administrators"
    lower(input.properties.administratorType) != "activedirectory"
}

db_ad_admin_err = "SQL servers which do not have Azure Active Directory admin configured" {
    db_ad_admin == false
}
