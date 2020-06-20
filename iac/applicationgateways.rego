package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/applicationgateways

#
# Azure Application Gateway allows TLSv1.1 or lower (220)
#

default gw_tls = null

gw_tls {
    input.type == "Microsoft.Network/applicationGateways"
    lower(input.properties.sslPolicy.minProtocolVersion) == "tlsv1_2"
}

gw_tls {
    input.type == "Microsoft.Network/applicationGateways"
    lower(input.properties.sslPolicy.minProtocolVersion) == "tlsv1_3"
}

gw_tls = false {
    input.type == "Microsoft.Network/applicationGateways"
    lower(input.properties.sslPolicy.minProtocolVersion) != "tlsv1_2"
    lower(input.properties.sslPolicy.minProtocolVersion) != "tlsv1_3"
}

gw_tls_err = "Azure Application Gateway allows TLSv1.1 or lower" {
    gw_tls == false
}

#
# Azure Application Gateway does not have the WAF enabled (221)
#

default gw_waf = null

gw_waf {
    input.type == "Microsoft.Network/applicationGateways"
    input.properties.webApplicationFirewallConfiguration.enabled == true
}

gw_waf = false {
    input.type == "Microsoft.Network/applicationGateways"
    input.properties.webApplicationFirewallConfiguration.enabled != true
}

gw_waf_err = "Azure Application Gateway does not have the WAF enabled" {
    gw_waf == false
}
