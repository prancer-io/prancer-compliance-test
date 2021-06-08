#
# PR-AZR-0084
#

package rule
default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2014-04-01/servers/databases/transparentdataencryption

rulepass {
    lower(input.type) == "microsoft.sql/servers/databases/transparentdataencryption"
    input.properties.status == "Enabled"
}

metadata := {
    "Policy Code": "PR-AZR-0084",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "SQL databases has encryption disabled",
    "Policy Description": "Transparent data encryption protects Azure database against malicious activity. It performs real-time encryption and decryption of the database, related reinforcements, and exchange log records without requiring any changes to the application. It encrypts the storage of the entire database by using a symmetric key called the database encryption key.",
    "Compliance": ["CIS","CSA-CCM","HIPAA","ISO 27001","NIST 800","PCI-DSS"],
    "Resource Type": "microsoft.sql/servers/databases/transparentdataencryption",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2014-04-01/servers/databases/transparentdataencryption"
}
