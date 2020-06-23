package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups

#
# Internet connectivity via tcp over insecure port (3)
# Memcached DDoS attack attempted (5)
# RedisWannaMine vulnerable instances with active network traffic (7)
# Azure NSG allows SSH traffic from internet on port 22 (229)
# Azure NSG allows traffic from internet on port 3389 (230)
# Azure NSG having Inbound rule overly permissive to all TCP traffic from any source (231)
# Azure NSG having Inbound rule overly permissive to all UDP traffic from any source (232)
# Azure NSG having Inbound rule overly permissive to all traffic from Internet on TCP protocol (233)
# Azure NSG having Inbound rule overly permissive to all traffic from Internet on UDP protocol (234)
# Azure NSG having Inbound rule overly permissive to all traffic from Internet on any protocol (235)
# Azure NSG having Inbound rule overly permissive to allow all traffic from any source on any protocol (236)
# Azure NSG having Inbound rule overly permissive to allow all traffic from any source to any destination (237)
# Azure Network Security Group allows CIFS (238)
# Azure Network Security Group allows DNS (239/240)
# Azure Network Security Group allows FTP (241)
# Azure Network Security Group allows FTP-Data (242)
# Azure Network Security Group allows ICMP (243)
# Azure Network Security Group allows MSQL (244)
# Azure Network Security Group allows MySQL (245)
# Azure Network Security Group allows NetBIOS (246/247)
# Azure Network Security Group allows PostgreSQL (248)
# Azure Network Security Group allows SMTP (249)
# Azure Network Security Group allows SQLServer (250/251)
# Azure Network Security Group allows Telnet (252)
# Azure Network Security Group allows VNC Listener (253)
# Azure Network Security Group allows VNC Server (254)
# Azure Network Security Group allows Windows RPC (255)
# Azure Network Security Group allows Windows SMB (256)
# Publicly exposed DB Ports (6)
#

default nsg = null

iports := [
    "21", "22", "23", "25", "53", "80", "135", "137", "138", "445", "1434", "3306", 
    "4333", "5432", "5500", "5900", "6379", "11211"
]

# allowed in all
nsg_inbound[port] {
    port := iports[_]
    lower(input.type) == "microsoft.network/networksecuritygroups"
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == "*"
}

# allowed in port
nsg_inbound[port] {
    port := iports[_]
    lower(input.type) == "microsoft.network/networksecuritygroups"
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == port
}

# allowed in list
nsg_inbound[port] {
    port := iports[_]
    lower(input.type) == "microsoft.network/networksecuritygroups"
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.destinationAddressPrefix == "*"
    contains(rules.properties.destinationPortRange, "-")
    port_range := split(rules.properties.destinationPortRange, "-")
    to_number(port_range[0]) <= to_number(port)
    to_number(port_range[1]) >= to_number(port)
}

# allowed in list
nsg_inbound[port] {
    port := iports[_]
    lower(input.type) == "microsoft.network/networksecuritygroups"
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRanges[_] == iports[_]
}

# allowed in list range
nsg_inbound[port] {
    port := iports[_]
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.destinationAddressPrefix == "*"
    port_range := split(rules.properties.destinationPortRanges[_], "-")
    to_number(port_range[0]) <= to_number(port)
    to_number(port_range[1]) >= to_number(port)
}

nsg_inbound_err["Azure NSG having Inbound rule overly permissive to all TCP traffic from any source"] {
    lower(input.type) == "microsoft.network/networksecuritygroups"
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.protocol == "TCP"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == "*"
}

nsg_inbound_err["Azure NSG having Inbound rule overly permissive to all UDP traffic from any source"] {
    lower(input.type) == "microsoft.network/networksecuritygroups"
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.protocol == "UDP"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == "*"
}

nsg_inbound_err["Azure NSG having Inbound rule overly permissive to all traffic from Internet on TCP protocol"] {
    lower(input.type) == "microsoft.network/networksecuritygroups"
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.protocol == "TCP"
    rules.properties.sourceAddressPrefix == "*"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == "*"
}

nsg_inbound_err["Azure NSG having Inbound rule overly permissive to all UDP traffic from any source"] {
    lower(input.type) == "microsoft.network/networksecuritygroups"
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.protocol == "UDP"
    rules.properties.sourceAddressPrefix == "Internet"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == "*"
}

nsg_inbound_err["Azure NSG having Inbound rule overly permissive to all traffic from Internet on any protocol"] {
    lower(input.type) == "microsoft.network/networksecuritygroups"
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.protocol == "*"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == "*"
}

nsg_inbound_err["Azure NSG having Inbound rule overly permissive to allow all traffic from any source on any protocol"] {
    lower(input.type) == "microsoft.network/networksecuritygroups"
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.protocol == "*"
    rules.properties.sourceAddressPrefix == "*"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == "*"
}

nsg_inbound_err["Azure Network Security Group allows ICMP"] {
    lower(input.type) == "microsoft.network/networksecuritygroups"
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.protocol == "ICMP"
    rules.properties.sourceAddressPrefix == "*"
}

nsg_inbound_err["Internet connectivity via tcp over insecure port"] {
    to_number(nsg_inbound[_]) == 21
}

nsg_inbound_err["Internet connectivity via tcp over insecure port"] {
    to_number(nsg_inbound[_]) == 23
}

nsg_inbound_err["Internet connectivity via tcp over insecure port"] {
    to_number(nsg_inbound[_]) == 80
}

nsg_inbound_err["Memcached DDoS attack attempted"] {
    to_number(nsg_inbound[_]) == 11211
}

nsg_inbound_err["RedisWannaMine vulnerable instances with active network traffic"] {
    to_number(nsg_inbound[_]) == 6379
}

nsg_inbound_err["Azure NSG allows SSH traffic from internet on port 22"] {
    to_number(nsg_inbound[_]) == 22
}

nsg_inbound_err["Azure NSG allows traffic from internet on port 3389"] {
    to_number(nsg_inbound[_]) == 3389
}

nsg_inbound_err["Azure Network Security Group allows CIFS"] {
    to_number(nsg_inbound[_]) == 445
}

nsg_inbound_err["Azure Network Security Group allows Windows SMB"] {
    to_number(nsg_inbound[_]) == 445
}

nsg_inbound_err["Azure Network Security Group allows DNS"] {
    to_number(nsg_inbound[_]) == 53
}

nsg_inbound_err["Azure Network Security Group allows FTP"] {
    to_number(nsg_inbound[_]) == 21
}

nsg_inbound_err["Azure Network Security Group allows FTP-Data"] {
    to_number(nsg_inbound[_]) == 20
}

nsg_inbound_err["Azure Network Security Group allows MSQL"] {
    to_number(nsg_inbound[_]) == 4333
}

nsg_inbound_err["Azure Network Security Group allows MySQL"] {
    to_number(nsg_inbound[_]) == 3306
}

nsg_inbound_err["Azure Network Security Group allows NetBIOS"] {
    to_number(nsg_inbound[_]) == 137
}

nsg_inbound_err["Azure Network Security Group allows NetBIOS"] {
    to_number(nsg_inbound[_]) == 138
}

nsg_inbound_err["Azure Network Security Group allows PostgreSQL"] {
    to_number(nsg_inbound[_]) == 5432
}

nsg_inbound_err["Azure Network Security Group allows SMTP"] {
    to_number(nsg_inbound[_]) == 25
}

nsg_inbound_err["Azure Network Security Group allows SMTP"] {
    to_number(nsg_inbound[_]) == 1434
}

nsg_inbound_err["Azure Network Security Group allows Telnet"] {
    to_number(nsg_inbound[_]) == 23
}

nsg_inbound_err["Azure Network Security Group allows VNC Listener"] {
    to_number(nsg_inbound[_]) == 5500
}

nsg_inbound_err["Azure Network Security Group allows VNC Server"] {
    to_number(nsg_inbound[_]) == 5900
}

nsg_inbound_err["Azure Network Security Group allows Windows RPC"] {
    to_number(nsg_inbound[_]) == 135
}

#
# Instance is communicating with ports known to mine Bitcoin (1)
# Instance is communicating with ports known to mine Ethereum (2)
# Azure NSG with Outbound rule to allow all traffic to any source (257)
#

oports := ["8332", "8333", "8545", "30303"]

# allowed in all
nsg_outbound[port] {
    port := oports[_]
    lower(input.type) == "microsoft.network/networksecuritygroups"
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Outbound"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == "*"
}

# allowed in port
nsg_outbound[port] {
    port := oports[_]
    lower(input.type) == "microsoft.network/networksecuritygroups"
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Outbound"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == port
}

# allowed in list
nsg_outbound[port] {
    port := oports[_]
    lower(input.type) == "microsoft.network/networksecuritygroups"
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Outbound"
    rules.properties.destinationAddressPrefix == "*"
    contains(rules.properties.destinationPortRange, "-")
    port_range := split(rules.properties.destinationPortRange, "-")
    to_number(port_range[0]) <= to_number(port)
    to_number(port_range[1]) >= to_number(port)
}

# allowed in list
nsg_outbound[port] {
    port := oports[_]
    lower(input.type) == "microsoft.network/networksecuritygroups"
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Outbound"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRanges[_] == oports[_]
}

# allowed in list range
nsg_outbound[port] {
    port := oports[_]
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Outbound"
    rules.properties.destinationAddressPrefix == "*"
    port_range := split(rules.properties.destinationPortRanges[_], "-")
    to_number(port_range[0]) <= to_number(port)
    to_number(port_range[1]) >= to_number(port)
}

nsg_outbound_err["Azure NSG with Outbound rule to allow all traffic to any source"] {
    port := oports[_]
    lower(input.type) == "microsoft.network/networksecuritygroups"
    rules := input.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Outbound"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == "*"
}

nsg_outbound_err["Instance is communicating with ports known to mine Bitcoin"] {
    to_number(nsg_outbound[_]) == 8332
}

nsg_outbound_err["Instance is communicating with ports known to mine Bitcoin"] {
    to_number(nsg_outbound[_]) == 8333
}

nsg_outbound_err["Instance is communicating with ports known to mine Ethereum"] {
    to_number(nsg_outbound[_]) == 8545
}

nsg_outbound_err["Instance is communicating with ports known to mine Ethereum"] {
    to_number(nsg_outbound[_]) == 30303
}

nsg {
    lower(input.type) == "microsoft.network/networksecuritygroups"
    count(nsg_inbound_err) == 0
    count(nsg_outbound_err) == 0
}

nsg = false {
    count(nsg_inbound_err) > 0
}

nsg = false {
    count(nsg_outbound_err) > 0
}

nsg_err = nsg_outbound_err | nsg_inbound_err {
    nsg == false
}
