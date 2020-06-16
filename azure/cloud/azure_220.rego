package rule
default rulepass = false

# https://docs.microsoft.com/en-us/rest/api/application-gateway/applicationgateways/get
# https://resources.azure.com/subscriptions/db3667b7-cef9-4523-8e45-e2d9ed4518ab/resourceGroups/hardikResourceGroup/providers/Microsoft.Network/applicationGateways/hardikApplicationGateway

rulepass {
   input.properties.sslPolicy.minProtocolVersion == "TLSv1_2"
}

rulepass {
   input.properties.sslPolicy.minProtocolVersion == "TLSv1_3"
}
