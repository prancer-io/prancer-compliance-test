#
# PR-AZR-0011
#

package rule
default rulepass = false

# https://docs.microsoft.com/en-us/rest/api/application-gateway/applicationgateways/get
# https://resources.azure.com/subscriptions/db3667b7-cef9-4523-8e45-e2d9ed4518ab/resourceGroups/hardikResourceGroup/providers/Microsoft.Network/applicationGateways/hardikApplicationGateway

rulepass {
    lower(input.type) == "microsoft.network/applicationgateways"
    input.properties.sslPolicy.minProtocolVersion == "TLSv1_2"
}

rulepass {
    lower(input.type) == "microsoft.network/applicationgateways"
    input.properties.sslPolicy.minProtocolVersion == "TLSv1_3"
}

metadata := {
    "Policy Code": "PR-AZR-0011",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure Application Gateway allows TLSv1.1 or lower",
    "Policy Description": "The Application Gateway supports end-to-end SSL encryption using multiple TLS versions and by default, it supports TLS version 1.0 as the minimum version.</br> </br> This policy identifies the Application Gateway instances that are configured to use TLS versions 1.1 or lower as the minimum protocol version. As a best practice set the MinProtocolVersion to TLSv1.2 (if you use custom SSL policy) or use the predefined â€˜AppGwSslPolicy20170401Sâ€™ policy.",
    "Resource Type": "microsoft.network/applicationgateways",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/application-gateway/applicationgateways/get"
}
