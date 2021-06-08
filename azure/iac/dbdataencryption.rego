package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2014-04-01/servers/databases/transparentdataencryption

#
# PR-AZR-0084-ARM
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

db_encrypt_metadata := {
    "Policy Code": "PR-AZR-0084-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "SQL databases has encryption disabled",
    "Policy Description": "Transparent data encryption protects Azure database against malicious activity. It performs real-time encryption and decryption of the database, related reinforcements, and exchange log records without requiring any changes to the application. It encrypts the storage of the entire database by using a symmetric key called the database encryption key.",
    "Compliance": ["CIS","CSA-CCM","HIPAA","ISO 27001","NIST 800","PCI-DSS"],
    "Resource Type": "microsoft.sql/servers/databases/transparentdataencryption",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2014-04-01/servers/databases/transparentdataencryption"
}

