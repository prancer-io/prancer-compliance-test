package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/databases/auditingsettings

rulepass {
	input.properties.state == "Enabled"
    input.properties.emailAccountAdmins == true
}
