package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2014-04-01/servers/databases/transparentdataencryption

#
# SQL databases has encryption disabled (293)
#

default db_encrypt = null

azure_attribute_absence["db_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/transparentdataencryption"
    not resource.properties.status
}

azure_issue["db_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/transparentdataencryption"
    lower(resource.properties.status) != "enabled"
}

db_encrypt {
    lower(input.resources[_].type) == "microsoft.sql/servers/databases/transparentdataencryption"
    not azure_issue["db_encrypt"]
    not azure_attribute_absence["db_encrypt"]
}

db_encrypt = false {
    azure_issue["db_encrypt"]
}

db_encrypt = false {
    azure_attribute_absence["db_encrypt"]
}

db_encrypt_err = "SQL databases has encryption disabled" {
    azure_issue["db_encrypt"]
}

db_encrypt_miss_err = "DB encryption attribute status missing in the resource" {
    azure_attribute_absence["db_encrypt"]
}

