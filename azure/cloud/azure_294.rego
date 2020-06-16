package rule
default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2019-06-01-preview/servers/administrators

rulepass {
	input.properties.administratorType == "ActiveDirectory"
}
