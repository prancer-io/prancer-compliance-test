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

azure_issue["db_ad_admin"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/administrators"
    lower(resource.properties.administratorType) != "activedirectory"
}

db_ad_admin {
    lower(input.resources[_].type) == "microsoft.sql/servers/administrators"
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
