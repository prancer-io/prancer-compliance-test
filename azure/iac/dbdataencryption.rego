package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2014-04-01/servers/databases/transparentdataencryption

#
# SQL databases has encryption disabled (293)
#

default db_encrypt = null

db_encrypt {
    lower(input.type) == "microsoft.sql/servers/databases/transparentdataencryption"
    lower(input.properties.status) == "enabled"
}

db_encrypt = false {
    lower(input.type) == "microsoft.sql/servers/databases/transparentdataencryption"
    lower(input.properties.status) != "enabled"
}

db_encrypt_err = "SQL databases has encryption disabled" {
    db_encrypt == false
}
