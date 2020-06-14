package rule
default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2014-04-01/servers/databases/transparentdataencryption

rulepass {
	input.properties.status == "Enabled"
}
