package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups

iports := [
    "20", "21", "22", "23", "25", "53", "80", "135", "137", "138", "445", "1270", "1521", 
    "3306", "3389", "4333", "5000", "5432", "5500", "5900", "5984", "5985", "5986", "6379", "6380", "9042", "11211",
    "27017", "28015", "29015", "50000"
]

# allowed in all
nsg_inbound[port] {
    resource := input.resources[_]
    port := iports[_]
    lower(resource.type) == "microsoft.network/networksecuritygroups"
    rules := resource.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == "*"
}

# allowed in port
nsg_inbound[port] {
    resource := input.resources[_]
    port := iports[_]
    lower(resource.type) == "microsoft.network/networksecuritygroups"
    rules := resource.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == port
}

# allowed in range
nsg_inbound[port] {
    resource := input.resources[_]
    port := iports[_]
    lower(resource.type) == "microsoft.network/networksecuritygroups"
    rules := resource.properties.securityRules[_]
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
    resource := input.resources[_]
    port := iports[_]
    lower(resource.type) == "microsoft.network/networksecuritygroups"
    rules := resource.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRanges[_] == port
}

# allowed in list range
nsg_inbound[port] {
    resource := input.resources[_]
    port := iports[_]
    lower(resource.type) == "microsoft.network/networksecuritygroups"
    rules := resource.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.destinationAddressPrefix == "*"
    port_range := split(rules.properties.destinationPortRanges[_], "-")
    to_number(port_range[0]) <= to_number(port)
    to_number(port_range[1]) >= to_number(port)
}

#
# PR-AZR-ARM-NSG-001
#

default nsg_in_tcp_all_src = null

azure_issue["nsg_in_tcp_all_src"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networksecuritygroups"
    rules := resource.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.protocol == "TCP"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == "*"
}

azure_issue["nsg_in_tcp_all_src"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networksecuritygroups"
    rules := resource.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.protocol == "*"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == "*"
}

nsg_in_tcp_all_src {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["nsg_in_tcp_all_src"]
}

nsg_in_tcp_all_src = false {
    azure_issue["nsg_in_tcp_all_src"]
}

nsg_in_tcp_all_src_err = "Azure NSG having Inbound rule overly permissive to all TCP traffic from any source" {
    azure_issue["nsg_in_tcp_all_src"]
}

nsg_in_tcp_all_src_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Network Security Group (NSG) having Inbound rule overly permissive to all TCP traffic from any source",
    "Policy Description": "This policy identifies Azure Network Security Groups (NSGs) which are overly permissive to open TCP traffic from any source. A network security group contains a list of security rules that allow or deny inbound or outbound network traffic based on source or destination IP address, port, and protocol. As a best practice, it is recommended to configure NSGs to restrict traffic from known sources, allowing only authorized protocols and ports.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

#
# PR-AZR-ARM-NSG-002
#

default nsg_in_udp_all_src = null

azure_issue["nsg_in_udp_all_src"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networksecuritygroups"
    rules := resource.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.protocol == "UDP"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == "*"
}

azure_issue["nsg_in_udp_all_src"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networksecuritygroups"
    rules := resource.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.protocol == "*"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == "*"
}

nsg_in_udp_all_src {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["nsg_in_udp_all_src"]
}

nsg_in_udp_all_src = false {
    azure_issue["nsg_in_udp_all_src"]
}

nsg_in_udp_all_src_err = "Azure NSG having Inbound rule overly permissive to all UDP traffic from any source" {
    azure_issue["nsg_in_udp_all_src"]
}

nsg_in_udp_all_src_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Network Security Group (NSG) having Inbound rule overly permissive to all UDP traffic from any source",
    "Policy Description": "This policy identifies Azure Network Security Groups (NSGs) which are overly permissive to open UDP traffic from any source. A network security group contains a list of security rules that allow or deny inbound or outbound network traffic based on source or destination IP address, port, and protocol. As a best practice, it is recommended to configure NSGs to restrict traffic from known sources, allowing only authorized protocols and ports.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

#
# PR-AZR-ARM-NSG-003
#

default nsg_in_tcp_all = null

azure_issue["nsg_in_tcp_all"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networksecuritygroups"
    rules := resource.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.protocol == "TCP"
    rules.properties.sourceAddressPrefix == "*"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == "*"
}

azure_issue["nsg_in_tcp_all"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networksecuritygroups"
    rules := resource.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.protocol == "*"
    rules.properties.sourceAddressPrefix == "*"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == "*"
}

nsg_in_tcp_all {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["nsg_in_tcp_all"]
}

nsg_in_tcp_all = false {
    azure_issue["nsg_in_tcp_all"]
}

nsg_in_tcp_all_err = "Azure NSG having Inbound rule overly permissive to all traffic from Internet on TCP protocol" {
    azure_issue["nsg_in_tcp_all"]
}

nsg_in_tcp_all_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-003",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Network Security Group (NSG) having Inbound rule overly permissive to all traffic from Internet on TCP protocol",
    "Policy Description": "This policy identifies Azure Network Security Groups (NSGs) which are overly permissive to all traffic from Internet on TCP protocol. A network security group contains a list of security rules that allow or deny inbound or outbound network traffic based on source or destination IP address, port, and protocol. As a best practice, it is recommended to configure NSGs to restrict traffic from known sources, allowing only authorized protocols and ports.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

#
# PR-AZR-ARM-NSG-004
#

default nsg_in_udp_all = null

azure_issue["nsg_in_udp_all"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networksecuritygroups"
    rules := resource.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.protocol == "UDP"
    rules.properties.sourceAddressPrefix == "Internet"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == "*"
}

azure_issue["nsg_in_udp_all"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networksecuritygroups"
    rules := resource.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.protocol == "*"
    rules.properties.sourceAddressPrefix == "Internet"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == "*"
}

nsg_in_udp_all {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["nsg_in_udp_all"]
}

nsg_in_udp_all = false {
    azure_issue["nsg_in_udp_all"]
}

nsg_in_udp_all_err = "Azure NSG having Inbound rule overly permissive to all UDP traffic from any source" {
    azure_issue["nsg_in_udp_all"]
}

nsg_in_udp_all_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-004",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Network Security Group (NSG) having Inbound rule overly permissive to all traffic from Internet on UDP protocol",
    "Policy Description": "This policy identifies Azure Network Security Groups (NSGs) which are overly permissive to all traffic from Internet on UDP protocol. A network security group contains a list of security rules that allow or deny inbound or outbound network traffic based on source or destination IP address, port, and protocol. As a best practice, it is recommended to configure NSGs to restrict traffic from known sources, allowing only authorized protocols and ports.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

#
# PR-AZR-ARM-NSG-005
#

default nsg_in_all = null

azure_issue["nsg_in_all"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networksecuritygroups"
    rules := resource.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.protocol == "*"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == "*"
}

nsg_in_all {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["nsg_in_all"]
}

nsg_in_all = false {
    azure_issue["nsg_in_all"]
}

nsg_in_all_err = "Azure NSG having Inbound rule overly permissive to all traffic from Internet on any protocol" {
    azure_issue["nsg_in_all"]
}

nsg_in_all_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-005",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Network Security Group (NSG) having Inbound rule overly permissive to allow all traffic from any source to any destination (TJX)",
    "Policy Description": "This policy identifies NSGs which allows incoming traffic from any source. A network security group contains a list of security rules that allow or deny inbound or outbound network traffic based on source or destination IP address, port, and protocol. As a best practice, it is recommended to configure NSGs to restrict traffic from known sources on authorized protocols and ports.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

#
# PR-AZR-ARM-NSG-006
#

default nsg_in_all_src = null

azure_issue["nsg_in_all_src"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networksecuritygroups"
    rules := resource.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.protocol == "*"
    rules.properties.sourceAddressPrefix == "*"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == "*"
}

nsg_in_all_src {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["nsg_in_all_src"]
}

nsg_in_all_src = false {
    azure_issue["nsg_in_all_src"]
}

nsg_in_all_src_err = "Azure NSG having Inbound rule overly permissive to allow all traffic from any source on any protocol" {
    azure_issue["nsg_in_all_src"]
}

nsg_in_all_src_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-006",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Network Security Group (NSG) having Inbound rule overly permissive to all traffic from Internet on any protocol",
    "Policy Description": "This policy identifies Azure Network Security Groups (NSGs) which are overly permissive to all traffic from Internet on any protocol. A network security group contains a list of security rules that allow or deny inbound or outbound network traffic based on source or destination IP address, port, and protocol. As a best practice, it is recommended to configure NSGs to restrict traffic from known sources, allowing only authorized protocols and ports.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

#
# PR-AZR-ARM-NSG-007
#

default nsg_in_all_dst = null

azure_issue["nsg_in_all_dst"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networksecuritygroups"
    rules := resource.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.protocol == "*"
    rules.properties.sourceAddressPrefix == "*"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == "*"
}

nsg_in_all_dst {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["nsg_in_all_dst"]
}

nsg_in_all_dst = false {
    azure_issue["nsg_in_all_dst"]
}

nsg_in_all_dst_err = "Azure NSG having Inbound rule overly permissive to allow all traffic from any source to any destination" {
    azure_issue["nsg_in_all_dst"]
}

nsg_in_all_dst_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-007",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Network Security Group (NSG) has an Inbound rule overly permissive to allow all traffic from any source on any destination",
    "Policy Description": "This policy identifies NSGs which allows incoming traffic from any source. A network security group contains a list of security rules that allow or deny inbound or outbound network traffic based on source or destination IP address, port, and protocol. As a best practice, it is recommended to configure NSGs to restrict traffic from known sources on authorized protocols and ports.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}


#
# PR-AZR-ARM-NSG-008
#

default nsg_allow_icmp = null

azure_issue["nsg_allow_icmp"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networksecuritygroups"
    rules := resource.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.protocol == "ICMP"
    rules.properties.sourceAddressPrefix == "*"
}

azure_issue["nsg_allow_icmp"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networksecuritygroups"
    rules := resource.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Inbound"
    rules.properties.protocol == "*"
    rules.properties.sourceAddressPrefix == "*"
}

nsg_allow_icmp {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["nsg_allow_icmp"]
}

nsg_allow_icmp = false {
    azure_issue["nsg_allow_icmp"]
}

nsg_allow_icmp_err = "Azure NSG Inbound rule overly permissive currently allowing ICMP (Ping)" {
    azure_issue["nsg_allow_icmp"]
}

nsg_allow_icmp_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-008",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Network Security Group allow ICMP (Ping)",
    "Policy Description": "ICMP is used by devices to communicate error messages and status. While ICMP is useful for  diagnostics and troubleshooting, it can also be used to exploit or disrupt systems.<br><br>This policy detects any NSG rule that allows ICMP (Ping) traffic from the internet. Review your list of NSG rules to ensure that your resources are not exposed.<br>As a best practice, restrict ICMP (Ping) solely to known static IP addresses. Limit the access list to include known hosts, services, or specific employees only.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

#
# PR-AZR-ARM-NSG-009
#

default inbound_port_21 = null

azure_issue["inbound_port_21"] {
    to_number(nsg_inbound[_]) == 21
}

inbound_port_21 {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["inbound_port_21"]
}

inbound_port_21 = false {
    azure_issue["inbound_port_21"]
}

inbound_port_21_err = "Azure Network Security Group allows FTP" {
    azure_issue["inbound_port_21"]
}

inbound_port_21_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-009",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Network Security Group allows FTP (TCP Port 21)",
    "Policy Description": "This policy detects any NSG rule that allows FTP traffic on TCP port 21 from the internet. Review your list of NSG rules to ensure that your resources are not exposed.<br>As a best practice, restrict FTP solely to known static IP addresses. Limit the access list to include known hosts, services, or specific employees only.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

#
# PR-AZR-ARM-NSG-010
#

default inbound_insecure_port = null

azure_issue["inbound_insecure_port"] {
    to_number(nsg_inbound[_]) == 21
}

azure_issue["inbound_insecure_port"] {
    to_number(nsg_inbound[_]) == 23
}

azure_issue["inbound_insecure_port"] {
    to_number(nsg_inbound[_]) == 80
}

inbound_insecure_port {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["inbound_insecure_port"]
}

inbound_insecure_port = false {
    azure_issue["inbound_insecure_port"]
}

inbound_insecure_port_err = "Internet connectivity via tcp over insecure port" {
    azure_issue["inbound_insecure_port"]
}

inbound_insecure_port_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-010",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Internet connectivity via tcp over insecure port should be prevented",
    "Policy Description": "Identify network traffic coming from internet which is plain text FTP, Telnet or HTTP from Internet.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

#
# PR-AZR-ARM-NSG-011
#

default inbound_port_11211 = null

azure_issue["inbound_port_11211"] {
    to_number(nsg_inbound[_]) == 11211
}

inbound_port_11211 {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["inbound_port_11211"]
}

inbound_port_11211 = false {
    azure_issue["inbound_port_11211"]
}

inbound_port_11211_err = "Memcached DDoS attack attempted" {
    azure_issue["inbound_port_11211"]
}

inbound_port_11211_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-011",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Memcached DDoS attack attempt should be prevented",
    "Policy Description": "Memcached is a general-purpose distributed memory caching system. It is often used to speed up dynamic database-driven websites by caching data and objects in RAM to reduce the number of times an external data source (such as a database or API) must be read. It is reported that Memcache versions 1.5.5 and below are vulnerable to DDoS amplification attack. This policy aims at finding such attacks and generate alerts.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

#
# PR-AZR-ARM-NSG-012
#

default inbound_port_6379 = null

azure_issue["inbound_port_6379"] {
    to_number(nsg_inbound[_]) == 6379
}

inbound_port_6379 {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["inbound_port_6379"]
}

inbound_port_6379 = false {
    azure_issue["inbound_port_6379"]
}

inbound_port_6379_err = "RedisWannaMine vulnerable instances with active network traffic" {
    azure_issue["inbound_port_6379"]
}

inbound_port_6379_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-012",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "RedisWannaMine vulnerable instances with active network traffic should be locked down",
    "Policy Description": "RedisWannaMine is cryptojacking attack which aims at both database servers and application servers via remote code execution, exploiting an Apache Struts vulnerability. To inject cryptocurrency mining malware, RedWannaMine uses a transmission control protocol (TCP) scanner to check open port 445 of SMB and scans vulnerable Redis server database over port 6379(tcp), so that it can use EternalBlue to spread further.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

#
# PR-AZR-ARM-NSG-013
#

default inbound_port_dbs = null

azure_issue["inbound_port_dbs"] {
    to_number(nsg_inbound[_]) == 1433
}

azure_issue["inbound_port_dbs"] {
    to_number(nsg_inbound[_]) == 1521
}

azure_issue["inbound_port_dbs"] {
    to_number(nsg_inbound[_]) == 3306
}

azure_issue["inbound_port_dbs"] {
    to_number(nsg_inbound[_]) == 5000
}

azure_issue["inbound_port_dbs"] {
    to_number(nsg_inbound[_]) == 5432
}

azure_issue["inbound_port_dbs"] {
    to_number(nsg_inbound[_]) == 5984
}

azure_issue["inbound_port_dbs"] {
    to_number(nsg_inbound[_]) == 6379
}

azure_issue["inbound_port_dbs"] {
    to_number(nsg_inbound[_]) == 6380
}

azure_issue["inbound_port_dbs"] {
    to_number(nsg_inbound[_]) == 9042
}

azure_issue["inbound_port_dbs"] {
    to_number(nsg_inbound[_]) == 11211
}

azure_issue["inbound_port_dbs"] {
    to_number(nsg_inbound[_]) == 27017
}

azure_issue["inbound_port_dbs"] {
    to_number(nsg_inbound[_]) == 28015
}

azure_issue["inbound_port_dbs"] {
    to_number(nsg_inbound[_]) == 29015
}

azure_issue["inbound_port_dbs"] {
    to_number(nsg_inbound[_]) == 50000
}

inbound_port_dbs {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["inbound_port_dbs"]
}

inbound_port_dbs = false {
    azure_issue["inbound_port_dbs"]
}

inbound_port_dbs_err = "Publicly exposed DB Ports" {
    azure_issue["inbound_port_dbs"]
}

inbound_port_dbs_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-013",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Publicly should not expose DB Ports",
    "Policy Description": "DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

#
# PR-AZR-ARM-NSG-014
#

default inbound_port_22 = null

azure_issue["inbound_port_22"] {
    to_number(nsg_inbound[_]) == 22
}

inbound_port_22 {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["inbound_port_22"]
}

inbound_port_22 = false {
    azure_issue["inbound_port_22"]
}

inbound_port_22_err = "Azure NSG allows SSH traffic from internet on port 22" {
    azure_issue["inbound_port_22"]
}

inbound_port_22_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-014",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Network Security Group (NSG) allows SSH traffic from internet on port 22",
    "Policy Description": "Blocking SSH port 22 will protect users from attacks like Account compromise.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

#
# PR-AZR-ARM-NSG-015
#

default inbound_port_3389 = null

azure_issue["inbound_port_3389"] {
    to_number(nsg_inbound[_]) == 3389
}

inbound_port_3389 {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["inbound_port_3389"]
}

inbound_port_3389 = false {
    azure_issue["inbound_port_3389"]
}

inbound_port_3389_err = "Azure NSG allows traffic from internet on port 3389" {
    azure_issue["inbound_port_3389"]
}

inbound_port_3389_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-015",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Network Security Group (NSG) allows traffic from internet on port 3389",
    "Policy Description": "Blocking RDP port 3389 will protect users from attacks like account compromise, Denial of service and ransomware.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

#

# PR-AZR-ARM-NSG-016
#

default inbound_port_445 = null

azure_issue["inbound_port_445"] {
    to_number(nsg_inbound[_]) == 445
}

inbound_port_445 {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["inbound_port_445"]
}

inbound_port_445 = false {
    azure_issue["inbound_port_445"]
}

inbound_port_445_err = "Azure Network Security Group allows CIFS" {
    azure_issue["inbound_port_445"]
}


inbound_port_445_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-06",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Network Security Group allows CIFS (UDP Port 445)",
    "Policy Description": "This policy detects any NSG rule that allows CIFS traffic on UDP port 445 from the internet. Review your list of NSG rules to ensure that your resources are not exposed.<br>As a best practice, restrict CIFS solely to known static IP addresses. Limit the access list to include known hosts, services, or specific employees only.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

#
# PR-AZR-ARM-NSG-017
#
 
default inbound_omi_port_blocked = null

azure_issue["inbound_omi_port_blocked"] {
    to_number(nsg_inbound[_]) == 5985
}
 
azure_issue["inbound_omi_port_blocked"] {
    to_number(nsg_inbound[_]) == 5986
}
 
azure_issue["inbound_omi_port_blocked"] {
    to_number(nsg_inbound[_]) == 1270
}

inbound_omi_port_blocked = false {
    azure_issue["inbound_omi_port_blocked"]
}
 
inbound_omi_port_blocked {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["inbound_omi_port_blocked"]
}
 
inbound_omi_port_blocked_err = "Azure Network Security Group (NSG) currently not protecting OMIGOD attack from internet" {
    azure_issue["inbound_omi_port_blocked"]
}
 
inbound_omi_port_blocked_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-017",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM",
    "Policy Title": "Azure Network Security Group (NSG) should protect OMIGOD attack from internet",
    "Policy Description": "Blocking OMI port 5985, 5986, 1270 will protect vnet/subnet/vms from OMIGOD attacks from internet.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

# PR-AZR-ARM-NSG-018
#

default inbound_port_53 = null

azure_issue["inbound_port_53"] {
    to_number(nsg_inbound[_]) == 53
}

inbound_port_53 {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["inbound_port_53"]
}

inbound_port_53 = false {
    azure_issue["inbound_port_53"]
}

inbound_port_53_err = "Azure Network Security Group allows DNS" {
    azure_issue["inbound_port_53"]
}

inbound_port_53_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-018",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Network Security Group allows DNS (UDP Port 53)",
    "Policy Description": "This policy detects any NSG rule that allows DNS traffic on UDP port 53 from the internet. Review your list of NSG rules to ensure that your resources are not exposed.<br>As a best practice, restrict DNS solely to known static IP addresses. Limit the access list to include known hosts, services, or specific employees only.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

#
# PR-AZR-ARM-NSG-019
#

default inbound_port_20 = null

azure_issue["inbound_port_20"] {
    to_number(nsg_inbound[_]) == 20
}

inbound_port_20 {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["inbound_port_20"]
}

inbound_port_20 = false {
    azure_issue["inbound_port_20"]
}

inbound_port_20_err = "Azure Network Security Group allows FTP-Data" {
    azure_issue["inbound_port_20"]
}


inbound_port_20_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-019",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Network Security Group allows FTP-Data (TCP Port 20)",
    "Policy Description": "This policy detects any NSG rule that allows FTP-Data traffic on TCP port 20 from the internet. Review your list of NSG rules to ensure that your resources are not exposed.<br>As a best practice, restrict FTP-Data solely to known static IP addresses. Limit the access list to include known hosts, services, or specific employees only.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

#
# PR-AZR-ARM-NSG-020
#

default inbound_port_4333 = null

azure_issue["inbound_port_4333"] {
    to_number(nsg_inbound[_]) == 4333
}

inbound_port_4333 {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["inbound_port_4333"]
}

inbound_port_4333 = false {
    azure_issue["inbound_port_4333"]
}

inbound_port_4333_err = "Azure Network Security Group allows MSQL" {
    azure_issue["inbound_port_4333"]
}

inbound_port_4333_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-020",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Network Security Group allows MSQL (TCP Port 4333)",
    "Policy Description": "This policy detects any NSG rule that allows MSQL traffic on TCP port 4333 from the internet. Review your list of NSG rules to ensure that your resources are not exposed.<br>As a best practice, restrict MSQL solely to known static IP addresses. Limit the access list to include known hosts, services, or specific employees only.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

#
# PR-AZR-ARM-NSG-021
#

default inbound_port_3306 = null

azure_issue["inbound_port_3306"] {
    to_number(nsg_inbound[_]) == 3306
}

inbound_port_3306 {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["inbound_port_3306"]
}

inbound_port_3306 = false {
    azure_issue["inbound_port_3306"]
}

inbound_port_3306_err = "Azure Network Security Group allows MySQL" {
    azure_issue["inbound_port_3306"]
}

inbound_port_3306_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-021",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Network Security Group allows MySQL (TCP Port 3306)",
    "Policy Description": "This policy detects any NSG rule that allows MySQL traffic on TCP port 3306 from the internet. Review your list of NSG rules to ensure that your resources are not exposed.<br>As a best practice, restrict MySQL solely to known static IP addresses. Limit the access list to include known hosts, services, or specific employees only.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

#
# PR-AZR-ARM-NSG-022

default inbound_port_netbios = null

azure_issue["inbound_port_netbios"] {
    to_number(nsg_inbound[_]) == 137
}

azure_issue["inbound_port_netbios"] {
    to_number(nsg_inbound[_]) == 138
}

inbound_port_netbios {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["inbound_port_netbios"]
}

inbound_port_netbios = false {
    azure_issue["inbound_port_netbios"]
}

inbound_port_netbios_err = "Azure Network Security Group allows NetBIOS" {
    azure_issue["inbound_port_netbios"]
}

inbound_port_netbios_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-022",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Network Security Group allows NetBIOS (UDP Port 137 and 138)",
    "Policy Description": "This policy detects any NSG rule that allows NetBIOS traffic on UDP port 137 and 138 from the internet. Review your list of NSG rules to ensure that your resources are not exposed.<br>As a best practice, restrict NetBIOS solely to known static IP addresses. Limit the access list to include known hosts, services, or specific employees only.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

#
# PR-AZR-ARM-NSG-023
#

default inbound_port_5432 = null

azure_issue["inbound_port_5432"] {
    to_number(nsg_inbound[_]) == 5432
}

inbound_port_5432 {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["inbound_port_5432"]
}

inbound_port_5432 = false {
    azure_issue["inbound_port_5432"]
}

inbound_port_5432_err = "Azure Network Security Group allows PostgreSQL" {
    azure_issue["inbound_port_5432"]
}

inbound_port_5432_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-023",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Network Security Group allows PostgreSQL (TCP Port 5432)",
    "Policy Description": "This policy detects any NSG rule that allows PostgreSQL traffic on TCP port 5432 from the internet. Review your list of NSG rules to ensure that your resources are not exposed.<br>As a best practice, restrict PostgreSQL solely to known static IP addresses. Limit the access list to include known hosts, services, or specific employees only.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

#
# PR-AZR-ARM-NSG-024
#

default inbound_port_25 = null

azure_issue["inbound_port_25"] {
    to_number(nsg_inbound[_]) == 25
}

inbound_port_25 {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["inbound_port_25"]
}

inbound_port_25 = false {
    azure_issue["inbound_port_25"]
}

inbound_port_25_err = "Azure Network Security Group allows SMTP" {
    azure_issue["inbound_port_25"]
}

inbound_port_25_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-024",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Network Security Group allows SMTP (TCP Port 25)",
    "Policy Description": "This policy detects any NSG rule that allows SMTP traffic on TCP port 25 from the internet. Review your list of NSG rules to ensure that your resources are not exposed.<br>As a best practice, restrict SMTP solely to known static IP addresses. Limit the access list to include known hosts, services, or specific employees only.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

#
# PR-AZR-ARM-NSG-025

# default inbound_port_sqlserver = null


# azure_issue["inbound_port_sqlserver"] {
#     to_number(nsg_inbound[_]) == 1433
# }


# azure_issue["inbound_port_sqlserver"] {
#     to_number(nsg_inbound[_]) == 1434
# }

# inbound_port_sqlserver {
#     lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
#     not azure_issue["inbound_port_sqlserver"]
# }

# inbound_port_sqlserver = false {
#     azure_issue["inbound_port_sqlserver"]
# }

# inbound_port_sqlserver_err = "Azure Network Security Group allows SQLServer" {
#     azure_issue["inbound_port_sqlserver"]
# }

# inbound_port_sqlserver_metadata := {
#     "Policy Code": "PR-AZR-ARM-NSG-025",
#     "Type": "IaC",
#     "Product": "AZR",
#     "Language": "ARM template",
#     "Policy Title": "Azure Network Security Group allows SQLServer (TCP Port 1433 and UDP Port 1434)",
#     "Policy Description": "This policy detects any NSG rule that allows SQLServer traffic on TCP Port 1433 and UDP port 1434 from the internet. Review your list of NSG rules to ensure that your resources are not exposed.<br>As a best practice, restrict SQLServer solely to known static IP addresses. Limit the access list to include known hosts, services, or specific employees only.",
#     "Resource Type": "microsoft.network/networksecuritygroups",
#     "Policy Help URL": "",
#     "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
# }


#
# PR-AZR-ARM-NSG-026
#

default inbound_port_23 = null

azure_issue["inbound_port_23"] {
    to_number(nsg_inbound[_]) == 23
}

inbound_port_23 {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["inbound_port_23"]
}

inbound_port_23 = false {
    azure_issue["inbound_port_23"]
}

inbound_port_23_err = "Azure Network Security Group allows Telnet" {
    azure_issue["inbound_port_23"]
}

inbound_port_23_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-026",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Network Security Group allows Telnet (TCP Port 23)",
    "Policy Description": "Telnet provides a plaintext connection to manage devices using the command line, and is less secure than SSH.<br>This policy detects any NSG rule that allows Telnet traffic on TCP port 23 from the internet. Review your list of NSG rules to ensure that your resources are not exposed.<br>As a best practice, restrict Telnet solely to known static IP addresses. Limit the access list to include known hosts, services, or specific employees only.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

#
# PR-AZR-ARM-NSG-027
#

default inbound_port_5500 = null

azure_issue["inbound_port_5500"] {
    to_number(nsg_inbound[_]) == 5500
}

inbound_port_5500 {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["inbound_port_5500"]
}

inbound_port_5500 = false {
    azure_issue["inbound_port_5500"]
}

inbound_port_5500_err = "Azure Network Security Group allows VNC Listener" {
    azure_issue["inbound_port_5500"]
}

inbound_port_5500_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-027",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Network Security Group allows VNC Listener (TCP Port 5500)",
    "Policy Description": "This policy detects any NSG rule that allows VNC Listener traffic on TCP port 5500 from the internet. Review your list of NSG rules to ensure that your resources are not exposed.<br>As a best practice, restrict VNC Listener solely to known static IP addresses. Limit the access list to include known hosts, services, or specific employees only.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

#
# PR-AZR-ARM-NSG-028
#

default inbound_port_5900 = null

azure_issue["inbound_port_5900"] {
    to_number(nsg_inbound[_]) == 5900
}

inbound_port_5900 {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["inbound_port_5900"]
}

inbound_port_5900 = false {
    azure_issue["inbound_port_5900"]
}

inbound_port_5900_err = "Azure Network Security Group allows VNC Server" {
    azure_issue["inbound_port_5900"]
}

inbound_port_5900_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-028",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Network Security Group allows VNC Server (TCP Port 5900)",
    "Policy Description": "This policy detects any NSG rule that allows VNC Server traffic on TCP port 5900 from the internet. Review your list of NSG rules to ensure that your resources are not exposed.<br>As a best practice, restrict VNC Server solely to known static IP addresses. Limit the access list to include known hosts, services, or specific employees only.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

#
# PR-AZR-ARM-NSG-029
#

default inbound_port_135 = null

azure_issue["inbound_port_135"] {
    to_number(nsg_inbound[_]) == 135
}

inbound_port_135 {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["inbound_port_135"]
}

inbound_port_135 = false {
    azure_issue["inbound_port_135"]
}

inbound_port_135_err = "Azure Network Security Group allows Windows RPC" {
    azure_issue["inbound_port_135"]
}

inbound_port_135_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-029",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Network Security Group allows Windows RPC (TCP Port 135)",
    "Policy Description": "This policy detects any NSG rule that allows Windows RPC traffic on TCP port 135 from the internet. Review your list of NSG rules to ensure that your resources are not exposed.<br>As a best practice, restrict Windows RPC solely to known static IP addresses. Limit the access list to include known hosts, services, or specific employees only.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}



oports := ["8332", "8333", "8545", "30303"]

# allowed in all
nsg_outbound[port] {
    port := oports[_]
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networksecuritygroups"
    rules := resource.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Outbound"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == "*"
}

# allowed in port
nsg_outbound[port] {
    port := oports[_]
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networksecuritygroups"
    rules := resource.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Outbound"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == port
}

# allowed in range
nsg_outbound[port] {
    port := oports[_]
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networksecuritygroups"
    rules := resource.properties.securityRules[_]
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
    rules.properties.destinationPortRanges[_] == port
}

# allowed in list range
nsg_outbound[port] {
    port := oports[_]
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networksecuritygroups"
    rules := resource.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Outbound"
    rules.properties.destinationAddressPrefix == "*"
    port_range := split(rules.properties.destinationPortRanges[_], "-")
    to_number(port_range[0]) <= to_number(port)
    to_number(port_range[1]) >= to_number(port)
}

#
# PR-AZR-ARM-NSG-030
#

default nsg_out_all = null

azure_issue["nsg_out_all"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networksecuritygroups"
    rules := resource.properties.securityRules[_]
    rules.properties.access == "Allow"
    rules.properties.direction == "Outbound"
    rules.properties.destinationAddressPrefix == "*"
    rules.properties.destinationPortRange == "*"
}

nsg_out_all {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["nsg_out_all"]
}

nsg_out_all = false {
    azure_issue["nsg_out_all"]
}

nsg_out_all_err = "Azure NSG with Outbound rule to allow all traffic to any source" {
    azure_issue["nsg_out_all"]
}

nsg_out_all_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-030",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Network Security Group with Outbound rule to allow all traffic to any source",
    "Policy Description": "This policy identifies NSGs which allows outgoing traffic to any source. A network security group contains a list of security rules that allow or deny inbound or outbound network traffic based on source or destination IP address, port, and protocol. As a best practice, it is recommended to configure NSGs to restrict traffic to known sources on authorized protocols and ports.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

#
# PR-AZR-ARM-NSG-031
#

default outbound_port_bitcoin = null

azure_issue["outbound_port_bitcoin"] {
    to_number(nsg_outbound[_]) == 8332
}

azure_issue["outbound_port_bitcoin"] {
    to_number(nsg_outbound[_]) == 8333
}

outbound_port_bitcoin {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["outbound_port_bitcoin"]
}

outbound_port_bitcoin = false {
    azure_issue["outbound_port_bitcoin"]
}

outbound_port_bitcoin_err = "Instance is communicating with ports known to mine Bitcoin" {
    azure_issue["outbound_port_bitcoin"]
}

outbound_port_bitcoin_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-031",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Instance is communicating with ports known to mine Bitcoin",
    "Policy Description": "Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

#
# PR-AZR-ARM-NSG-032
#

default outbound_port_ethereum = null

azure_issue["outbound_port_ethereum"] {
    to_number(nsg_outbound[_]) == 8545
}

azure_issue["outbound_port_ethereum"] {
    to_number(nsg_outbound[_]) == 30303
}

outbound_port_ethereum {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["outbound_port_ethereum"]
}

outbound_port_ethereum = false {
    azure_issue["outbound_port_ethereum"]
}

outbound_port_ethereum_err = "Instance is communicating with ports known to mine Ethereum" {
    azure_issue["outbound_port_ethereum"]
}

outbound_port_ethereum_metadata := {
    "Policy Code": "PR-AZR-ARM-NSG-032",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Instance is communicating with ports known to mine Ethereum",
    "Policy Description": "Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}
