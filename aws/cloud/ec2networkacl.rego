package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-network-acl-entry.html

#
# PR-AWS-CFR-NACL-001
#

default acl_all_icmp_ipv4 = true

acl_all_icmp_ipv4 = false {
    # lower(resource.Type) == "aws::ec2::networkaclentry"
    NetworkAcls := input.NetworkAcls[_]
    Entries := NetworkAcls.Entries[_]
    Entries.Egress != true
    to_number(Entries.Protocol) == 1
    Entries.CidrBlock == "0.0.0.0/0"
    lower(Entries.RuleAction) == "allow"
}

acl_all_icmp_ipv4 = false {
    # lower(resource.Type) == "aws::ec2::networkaclentry"
    NetworkAcls := input.NetworkAcls[_]
    Entries := NetworkAcls.Entries[_]
    Entries.Egress != true
    to_number(Entries.Protocol) == -1
    Entries.CidrBlock == "0.0.0.0/0"
    lower(Entries.RuleAction) == "allow"
}

acl_all_icmp_ipv4_err = "AWS Network ACLs with Outbound rule to allow All ICMP IPv4" {
    not acl_all_icmp_ipv4
}

acl_all_icmp_ipv4_metadata := {
    "Policy Code": "PR-AWS-CFR-NACL-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Network ACLs with Inbound rule to allow All ICMP IPv4",
    "Policy Description": "This policy identifies ACLs which allows traffic on all ICMP IPv4 protocol. A network access control list (ACL) is an optional layer of security for your VPC that acts as a firewall for controlling traffic in and out of one or more subnets. By default, ACL allows all inbound and outbound IPv4 traffic and, if applicable, IPv6 traffic. Inbound rules that allow unrestricted traffic to the internet can be a security risk. As a best practice, it is recommended to configure ACL to restrict traffic on authorized protocols.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-network-acl-entry.html"
}

#
# PR-AWS-CFR-NACL-002
#

default acl_all_icmp_ipv6 = true

acl_all_icmp_ipv6 = false {
    # lower(resource.Type) == "aws::ec2::networkaclentry"
    NetworkAcls := input.NetworkAcls[_]
    Entries := NetworkAcls.Entries[_]
    Entries.Egress != true
    to_number(Entries.Protocol) == 1
    Entries.Ipv6CidrBlock == "::/0"
    lower(Entries.RuleAction) == "allow"
}

acl_all_icmp_ipv6 = false {
    # lower(resource.Type) == "aws::ec2::networkaclentry"
    NetworkAcls := input.NetworkAcls[_]
    Entries := NetworkAcls.Entries[_]
    Entries.Egress != true
    to_number(Entries.Protocol) == -1
    Entries.Ipv6CidrBlock == "::/0"
    lower(Entries.RuleAction) == "allow"
}

acl_all_icmp_ipv6_err = "AWS Network ACLs with Inbound rule to allow All ICMP IPv6" {
    not acl_all_icmp_ipv6
}

acl_all_icmp_ipv6_metadata := {
    "Policy Code": "PR-AWS-CFR-NACL-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Network ACLs with Inbound rule to allow All ICMP IPv6",
    "Policy Description": "This policy identifies ACLs which allows traffic on all ICMP IPv6 protocol. A network access control list (ACL) is an optional layer of security for your VPC that acts as a firewall for controlling traffic in and out of one or more subnets. By default, ACL allows all inbound and outbound IPv4 traffic and, if applicable, IPv6 traffic. Inbound rules that allow unrestricted traffic to the internet can be a security risk. As a best practice, it is recommended to configure ACL to restrict traffic on authorized protocols.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-network-acl-entry.html"
}

#
# PR-AWS-CFR-NACL-003
#

default acl_all_traffic = true

acl_all_traffic = false {
    # lower(resource.Type) == "aws::ec2::networkaclentry"
    NetworkAcls := input.NetworkAcls[_]
    Entries := NetworkAcls.Entries[_]
    Entries.Egress != true
    to_number(Entries.Protocol) == -1
    Entries.CidrBlock == "0.0.0.0/0"
    lower(Entries.RuleAction) == "allow"
}

acl_all_traffic_err = "AWS Network ACLs with Inbound rule to allow All Traffic" {
    not acl_all_traffic
}

acl_all_traffic_metadata := {
    "Policy Code": "PR-AWS-CFR-NACL-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Network ACLs with Inbound rule to allow All Traffic",
    "Policy Description": "This policy identifies ACLs which allows traffic on all protocols. A network access control list (ACL) is an optional layer of security for your VPC that acts as a firewall for controlling traffic in and out of one or more subnets. By default, ACL allows all inbound and outbound IPv4 traffic and, if applicable, IPv6 traffic. Inbound rules that allow unrestricted traffic to the internet can be a security risk. As a best practice, it is recommended to configure ACLs to restrict traffic on authorized protocols.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-network-acl-entry.html"
}

#
# PR-AWS-CFR-NACL-004
#

default acl_all_icmp_ipv4_out = true

acl_all_icmp_ipv4_out = false {
    # lower(resource.Type) == "aws::ec2::networkaclentry"
    NetworkAcls := input.NetworkAcls[_]
    Entries := NetworkAcls.Entries[_]
    Entries.Egress == true
    to_number(Entries.Protocol) == 1
    Entries.CidrBlock == "0.0.0.0/0"
    lower(Entries.RuleAction) == "allow"
}

acl_all_icmp_ipv4_out = false {
    # lower(resource.Type) == "aws::ec2::networkaclentry"
    NetworkAcls := input.NetworkAcls[_]
    Entries := NetworkAcls.Entries[_]
    Entries.Egress == true
    to_number(Entries.Protocol) == -1
    Entries.CidrBlock == "0.0.0.0/0"
    lower(Entries.RuleAction) == "allow"
}

acl_all_icmp_ipv4_out_err = "AWS Network ACLs with Outbound rule to allow All ICMP IPv4" {
    not acl_all_icmp_ipv4_out
}
acl_all_icmp_ipv4_out_metadata := {
    "Policy Code": "PR-AWS-CFR-NACL-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Network ACLs with Outbound rule to allow All ICMP IPv4",
    "Policy Description": "This policy identifies ACLs which allows traffic on all protocol. A network access control list (ACL) is an optional layer of security for your VPC that acts as a firewall for controlling traffic in and out of one or more subnets. By default, ACL allows all inbound and outbound IPv4 traffic and, if applicable, IPv6 traffic. Outbound rules that allow unrestricted traffic to the internet can be a security risk. As a best practice, it is recommended to configure ACL to restrict traffic on authorized protocols.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-network-acl-entry.html"
}

#
# PR-AWS-CFR-NACL-005
#

default acl_all_icmp_ipv6_out = true

acl_all_icmp_ipv6_out = false {
    # lower(resource.Type) == "aws::ec2::networkaclentry"
    NetworkAcls := input.NetworkAcls[_]
    Entries := NetworkAcls.Entries[_]
    Entries.Egress == true
    to_number(Entries.Protocol) == 1
    Entries.Ipv6CidrBlock == "::/0"
    lower(Entries.RuleAction) == "allow"
}

acl_all_icmp_ipv6_out = false {
    # lower(resource.Type) == "aws::ec2::networkaclentry"
    NetworkAcls := input.NetworkAcls[_]
    Entries := NetworkAcls.Entries[_]
    Entries.Egress == true
    to_number(Entries.Protocol) == -1
    Entries.Ipv6CidrBlock == "::/0"
    lower(Entries.RuleAction) == "allow"
}

acl_all_icmp_ipv6_out_err = "AWS Network ACLs with Outbound rule to allow All ICMP IPv6" {
    not acl_all_icmp_ipv6_out
}

acl_all_icmp_ipv6_out_metadata := {
    "Policy Code": "PR-AWS-CFR-NACL-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Network ACLs with Outbound rule to allow All ICMP IPv6",
    "Policy Description": "This policy identifies ACLs which allows traffic on all protocol. A network access control list (ACL) is an optional layer of security for your VPC that acts as a firewall for controlling traffic in and out of one or more subnets. By default, ACL allows all inbound and outbound IPv4 traffic and, if applicable, IPv6 traffic. Outbound rules that allow unrestricted traffic to the internet can be a security risk. As a best practice, it is recommended to configure ACL to restrict traffic on authorized protocols.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-network-acl-entry.html"
}

#
# PR-AWS-CFR-NACL-006
#

default acl_all_traffic_out = true

acl_all_traffic_out = false {
    # lower(resource.Type) == "aws::ec2::networkaclentry"
    NetworkAcls := input.NetworkAcls[_]
    Entries := NetworkAcls.Entries[_]
    Entries.Egress == true
    to_number(Entries.Protocol) == -1
    Entries.CidrBlock == "0.0.0.0/0"
    lower(Entries.RuleAction) == "allow"
}

acl_all_traffic_out_err = "AWS Network ACLs with Outbound rule to allow All Traffic" {
    not acl_all_traffic_out
}

acl_all_traffic_out_metadata := {
    "Policy Code": "PR-AWS-CFR-NACL-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Network ACLs with Outbound rule to allow All Traffic",
    "Policy Description": "This policy identifies ACLs which allows traffic on all protocols. A network access control list (ACL) is an optional layer of security for your VPC that acts as a firewall for controlling traffic in and out of one or more subnets. By default, ACL allows all inbound and outbound IPv4 traffic and, if applicable, IPv6 traffic. Outbound rules that allow unrestricted traffic to the internet can be a security risk. As a best practice, it is recommended to configure ACLs to restrict traffic on authorized protocols.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-network-acl-entry.html"
}


#
# PR-AWS-CFR-NACL-007
#

default acl_unrestricted_admin_port = true

acl_unrestricted_admin_port = false {
    # lower(resource.Type) == "aws::ec2::networkaclentry"
    NetworkAcls := input.NetworkAcls[_]
    Entries := NetworkAcls.Entries[_]
    Entries.Egress == false
    to_number(Entries.PortRange.From) <= 22
    to_number(Entries.PortRange.To) >= 22
    Entries.CidrBlock == "0.0.0.0/0"
    lower(Entries.RuleAction) == "allow"
}

acl_unrestricted_admin_port = false {
    # lower(resource.Type) == "aws::ec2::networkaclentry"
    NetworkAcls := input.NetworkAcls[_]
    Entries := NetworkAcls.Entries[_]
    Entries.Egress == false
    to_number(Entries.PortRange.From) <= 22
    to_number(Entries.PortRange.To) >= 22
    Entries.Ipv6CidrBlock == "::/0"
    lower(Entries.RuleAction) == "allow"
}

acl_unrestricted_admin_port = false {
    # lower(resource.Type) == "aws::ec2::networkaclentry"
    NetworkAcls := input.NetworkAcls[_]
    Entries := NetworkAcls.Entries[_]
    Entries.Egress == false
    to_number(Entries.PortRange.From) <= 3389
    to_number(Entries.PortRange.To) >= 3389
    Entries.CidrBlock == "0.0.0.0/0"
    lower(Entries.RuleAction) == "allow"
}

acl_unrestricted_admin_port = false {
    # lower(resource.Type) == "aws::ec2::networkaclentry"
    NetworkAcls := input.NetworkAcls[_]
    Entries := NetworkAcls.Entries[_]
    Entries.Egress == false
    to_number(Entries.PortRange.From) <= 3389
    to_number(Entries.PortRange.To) >= 3389
    Entries.Ipv6CidrBlock == "::/0"
    lower(Entries.RuleAction) == "allow"
}

acl_unrestricted_admin_port_err = "Unrestricted Inbound Traffic on Remote Server Administration Ports" {
    not acl_unrestricted_admin_port
}

acl_unrestricted_admin_port_metadata := {
    "Policy Code": "PR-AWS-CFR-NACL-007",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Unrestricted Inbound Traffic on Remote Server Administration Ports",
    "Policy Description": "Check your Amazon VPC Network Access Control Lists (NACLs) for inbound/ingress rules that allow unrestricted traffic (i.e. 0.0.0.0/0) on TCP ports 22 (SSH) and 3389 (RDP) and limit access to trusted IP addresses or IP ranges only in order to implement the Principle of Least Privilege (POLP) and reduce the attack surface at the subnet level.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-network-acl-entry.html"
}
