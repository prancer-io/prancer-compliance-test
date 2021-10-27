package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-network-acl-entry.html

#
# PR-AWS-CFR-NACL-001
#

default acl_all_icmp_ipv4 = null

aws_issue["acl_all_icmp_ipv4"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    lower(resource.Properties.Egress) != "true"
    to_number(resource.Properties.Protocol) == 1
    resource.Properties.CidrBlock == "0.0.0.0/0"
    lower(resource.Properties.RuleAction) == "allow"
}

source_path[{"ec2_monitoring": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    lower(resource.Properties.Egress) != "true"
    to_number(resource.Properties.Protocol) == 1
    resource.Properties.CidrBlock == "0.0.0.0/0"
    lower(resource.Properties.RuleAction) == "allow"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "CidrBlock"]
        ],
    }
}

aws_bool_issue["acl_all_icmp_ipv4"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    resource.Properties.Egress != true
    to_number(resource.Properties.Protocol) == 1
    resource.Properties.CidrBlock == "0.0.0.0/0"
    lower(resource.Properties.RuleAction) == "allow"
}

aws_issue["acl_all_icmp_ipv4"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    lower(resource.Properties.Egress) != "true"
    to_number(resource.Properties.Protocol) == -1
    resource.Properties.CidrBlock == "0.0.0.0/0"
    lower(resource.Properties.RuleAction) == "allow"
}

aws_bool_issue["acl_all_icmp_ipv4"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    resource.Properties.Egress != true
    to_number(resource.Properties.Protocol) == -1
    resource.Properties.CidrBlock == "0.0.0.0/0"
    lower(resource.Properties.RuleAction) == "allow"
}

acl_all_icmp_ipv4 {
    lower(input.Resources[i].Type) == "aws::ec2::networkaclentry"
    not aws_issue["acl_all_icmp_ipv4"]
    not aws_bool_issue["acl_all_icmp_ipv4"]
}

acl_all_icmp_ipv4 = false {
    aws_issue["acl_all_icmp_ipv4"]
}

acl_all_icmp_ipv4 = false {
    aws_bool_issue["acl_all_icmp_ipv4"]
}

acl_all_icmp_ipv4_err = "AWS Network ACLs with Outbound rule to allow All ICMP IPv4" {
    aws_issue["acl_all_icmp_ipv4"]
} else = "AWS Network ACLs with Outbound rule to allow All ICMP IPv4" {
    aws_bool_issue["acl_all_icmp_ipv4"]
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

default acl_all_icmp_ipv6 = null

aws_issue["acl_all_icmp_ipv6"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    lower(resource.Properties.Egress) != "true"
    to_number(resource.Properties.Protocol) == 1
    resource.Properties.Ipv6CidrBlock == "::/0"
    lower(resource.Properties.RuleAction) == "allow"
}

aws_bool_issue["acl_all_icmp_ipv6"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    resource.Properties.Egress != true
    to_number(resource.Properties.Protocol) == 1
    resource.Properties.Ipv6CidrBlock == "::/0"
    lower(resource.Properties.RuleAction) == "allow"
}

aws_issue["acl_all_icmp_ipv6"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    lower(resource.Properties.Egress) != "true"
    to_number(resource.Properties.Protocol) == -1
    resource.Properties.Ipv6CidrBlock == "::/0"
    lower(resource.Properties.RuleAction) == "allow"
}

aws_bool_issue["acl_all_icmp_ipv6"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    resource.Properties.Egress != true
    to_number(resource.Properties.Protocol) == -1
    resource.Properties.Ipv6CidrBlock == "::/0"
    lower(resource.Properties.RuleAction) == "allow"
}

acl_all_icmp_ipv6 {
    lower(input.Resources[i].Type) == "aws::ec2::networkaclentry"
    not aws_issue["acl_all_icmp_ipv6"]
    not aws_bool_issue["acl_all_icmp_ipv6"]
}

acl_all_icmp_ipv6 = false {
    aws_issue["acl_all_icmp_ipv6"]
}

acl_all_icmp_ipv6 = false {
    aws_bool_issue["acl_all_icmp_ipv6"]
}

acl_all_icmp_ipv6_err = "AWS Network ACLs with Inbound rule to allow All ICMP IPv6" {
    aws_issue["acl_all_icmp_ipv6"]
} else = "AWS Network ACLs with Inbound rule to allow All ICMP IPv6" {
    aws_bool_issue["acl_all_icmp_ipv6"]
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

default acl_all_traffic = null

aws_issue["acl_all_traffic"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    lower(resource.Properties.Egress) != "true"
    to_number(resource.Properties.Protocol) == -1
    resource.Properties.CidrBlock == "0.0.0.0/0"
    lower(resource.Properties.RuleAction) == "allow"
}

aws_bool_issue["acl_all_traffic"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    resource.Properties.Egress != true
    to_number(resource.Properties.Protocol) == -1
    resource.Properties.CidrBlock == "0.0.0.0/0"
    lower(resource.Properties.RuleAction) == "allow"
}


acl_all_traffic {
    lower(input.Resources[i].Type) == "aws::ec2::networkaclentry"
    not aws_issue["acl_all_traffic"]
    not aws_bool_issue["acl_all_traffic"]
}

acl_all_traffic = false {
    aws_issue["acl_all_traffic"]
}

acl_all_traffic = false {
    aws_bool_issue["acl_all_traffic"]
}

acl_all_traffic_err = "AWS Network ACLs with Inbound rule to allow All Traffic" {
    aws_issue["acl_all_traffic"]
} else = "AWS Network ACLs with Inbound rule to allow All Traffic" {
    aws_bool_issue["acl_all_traffic"]
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

default acl_all_icmp_ipv4_out = null

aws_issue["acl_all_icmp_ipv4_out"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    lower(resource.Properties.Egress) == "true"
    to_number(resource.Properties.Protocol) == 1
    resource.Properties.CidrBlock == "0.0.0.0/0"
    lower(resource.Properties.RuleAction) == "allow"
}

aws_bool_issue["acl_all_icmp_ipv4_out"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    resource.Properties.Egress == true
    to_number(resource.Properties.Protocol) == 1
    resource.Properties.CidrBlock == "0.0.0.0/0"
    lower(resource.Properties.RuleAction) == "allow"
}

aws_issue["acl_all_icmp_ipv4_out"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    lower(resource.Properties.Egress) == "true"
    to_number(resource.Properties.Protocol) == -1
    resource.Properties.CidrBlock == "0.0.0.0/0"
    lower(resource.Properties.RuleAction) == "allow"
}

aws_bool_issue["acl_all_icmp_ipv4_out"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    resource.Properties.Egress == true
    to_number(resource.Properties.Protocol) == -1
    resource.Properties.CidrBlock == "0.0.0.0/0"
    lower(resource.Properties.RuleAction) == "allow"
}

acl_all_icmp_ipv4_out {
    lower(input.Resources[i].Type) == "aws::ec2::networkaclentry"
    not aws_issue["acl_all_icmp_ipv4_out"]
    not aws_bool_issue["acl_all_icmp_ipv4_out"]
}

acl_all_icmp_ipv4_out = false {
    aws_issue["acl_all_icmp_ipv4_out"]
}

acl_all_icmp_ipv4_out = false {
    aws_bool_issue["acl_all_icmp_ipv4_out"]
}

acl_all_icmp_ipv4_out_err = "AWS Network ACLs with Outbound rule to allow All ICMP IPv4" {
    aws_issue["acl_all_icmp_ipv4_out"]
} else = "AWS Network ACLs with Outbound rule to allow All ICMP IPv4" {
    aws_bool_issue["acl_all_icmp_ipv4_out"]
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

default acl_all_icmp_ipv6_out = null

aws_issue["acl_all_icmp_ipv6_out"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    lower(resource.Properties.Egress) == "true"
    to_number(resource.Properties.Protocol) == 1
    resource.Properties.Ipv6CidrBlock == "::/0"
    lower(resource.Properties.RuleAction) == "allow"
}

aws_bool_issue["acl_all_icmp_ipv6_out"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    resource.Properties.Egress == true
    to_number(resource.Properties.Protocol) == 1
    resource.Properties.Ipv6CidrBlock == "::/0"
    lower(resource.Properties.RuleAction) == "allow"
}

aws_issue["acl_all_icmp_ipv6_out"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    lower(resource.Properties.Egress) == "true"
    to_number(resource.Properties.Protocol) == -1
    resource.Properties.Ipv6CidrBlock == "::/0"
    lower(resource.Properties.RuleAction) == "allow"
}

aws_bool_issue["acl_all_icmp_ipv6_out"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    resource.Properties.Egress == true
    to_number(resource.Properties.Protocol) == -1
    resource.Properties.Ipv6CidrBlock == "::/0"
    lower(resource.Properties.RuleAction) == "allow"
}

acl_all_icmp_ipv6_out {
    lower(input.Resources[i].Type) == "aws::ec2::networkaclentry"
    not aws_issue["acl_all_icmp_ipv6_out"]
    not aws_bool_issue["acl_all_icmp_ipv6_out"]
}

acl_all_icmp_ipv6_out = false {
    aws_issue["acl_all_icmp_ipv6_out"]
}

acl_all_icmp_ipv6_out = false {
    aws_bool_issue["acl_all_icmp_ipv6_out"]
}

acl_all_icmp_ipv6_out_err = "AWS Network ACLs with Outbound rule to allow All ICMP IPv6" {
    aws_issue["acl_all_icmp_ipv6_out"]
} else = "AWS Network ACLs with Outbound rule to allow All ICMP IPv6" {
    aws_bool_issue["acl_all_icmp_ipv6_out"]
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

default acl_all_traffic_out = null

aws_issue["acl_all_traffic_out"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    lower(resource.Properties.Egress) == "true"
    to_number(resource.Properties.Protocol) == -1
    resource.Properties.CidrBlock == "0.0.0.0/0"
    lower(resource.Properties.RuleAction) == "allow"
}

aws_bool_issue["acl_all_traffic_out"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    resource.Properties.Egress == true
    to_number(resource.Properties.Protocol) == -1
    resource.Properties.CidrBlock == "0.0.0.0/0"
    lower(resource.Properties.RuleAction) == "allow"
}

acl_all_traffic_out {
    lower(input.Resources[i].Type) == "aws::ec2::networkaclentry"
    not aws_issue["acl_all_traffic_out"]
    not aws_bool_issue["acl_all_traffic_out"]
}

acl_all_traffic_out = false {
    aws_issue["acl_all_traffic_out"]
}

acl_all_traffic_out = false {
    aws_bool_issue["acl_all_traffic_out"]
}

acl_all_traffic_out_err = "AWS Network ACLs with Outbound rule to allow All Traffic" {
    aws_issue["acl_all_traffic_out"]
} else = "AWS Network ACLs with Outbound rule to allow All Traffic" {
    aws_bool_issue["acl_all_traffic_out"]
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

default acl_unrestricted_admin_port = null

aws_issue["acl_unrestricted_admin_port"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    lower(resource.Properties.Egress) == "false"
    to_number(resource.Properties.PortRange.From) <= 22
    to_number(resource.Properties.PortRange.To) >= 22
    resource.Properties.CidrBlock == "0.0.0.0/0"
    lower(resource.Properties.RuleAction) == "allow"
}

aws_issue["acl_unrestricted_admin_port"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    lower(resource.Properties.Egress) == "false"
    to_number(resource.Properties.PortRange.From) <= 22
    to_number(resource.Properties.PortRange.To) >= 22
    resource.Properties.Ipv6CidrBlock == "::/0"
    lower(resource.Properties.RuleAction) == "allow"
}

aws_issue["acl_unrestricted_admin_port"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    lower(resource.Properties.Egress) == "false"
    to_number(resource.Properties.PortRange.From) <= 3389
    to_number(resource.Properties.PortRange.To) >= 3389
    resource.Properties.CidrBlock == "0.0.0.0/0"
    lower(resource.Properties.RuleAction) == "allow"
}

aws_issue["acl_unrestricted_admin_port"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    lower(resource.Properties.Egress) == "false"
    to_number(resource.Properties.PortRange.From) <= 3389
    to_number(resource.Properties.PortRange.To) >= 3389
    resource.Properties.Ipv6CidrBlock == "::/0"
    lower(resource.Properties.RuleAction) == "allow"
}


aws_bool_issue["acl_unrestricted_admin_port"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    resource.Properties.Egress == false
    to_number(resource.Properties.PortRange.From) <= 22
    to_number(resource.Properties.PortRange.To) >= 22
    resource.Properties.CidrBlock == "0.0.0.0/0"
    lower(resource.Properties.RuleAction) == "allow"
}

aws_bool_issue["acl_unrestricted_admin_port"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    resource.Properties.Egress == false
    to_number(resource.Properties.PortRange.From) <= 22
    to_number(resource.Properties.PortRange.To) >= 22
    resource.Properties.Ipv6CidrBlock == "::/0"
    lower(resource.Properties.RuleAction) == "allow"
}

aws_bool_issue["acl_unrestricted_admin_port"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    resource.Properties.Egress == false
    to_number(resource.Properties.PortRange.From) <= 3389
    to_number(resource.Properties.PortRange.To) >= 3389
    resource.Properties.CidrBlock == "0.0.0.0/0"
    lower(resource.Properties.RuleAction) == "allow"
}

aws_bool_issue["acl_unrestricted_admin_port"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::networkaclentry"
    resource.Properties.Egress == false
    to_number(resource.Properties.PortRange.From) <= 3389
    to_number(resource.Properties.PortRange.To) >= 3389
    resource.Properties.Ipv6CidrBlock == "::/0"
    lower(resource.Properties.RuleAction) == "allow"
}


acl_unrestricted_admin_port {
    lower(input.Resources[i].Type) == "aws::ec2::networkaclentry"
    not aws_issue["acl_unrestricted_admin_port"]
    not aws_bool_issue["acl_unrestricted_admin_port"]
}

acl_unrestricted_admin_port = false {
    aws_issue["acl_unrestricted_admin_port"]
}

acl_unrestricted_admin_port = false {
    aws_bool_issue["acl_unrestricted_admin_port"]
}

acl_unrestricted_admin_port_err = "Unrestricted Inbound Traffic on Remote Server Administration Ports" {
    aws_issue["acl_unrestricted_admin_port"]
} else = "Unrestricted Inbound Traffic on Remote Server Administration Ports" {
    aws_bool_issue["acl_unrestricted_admin_port"]
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
