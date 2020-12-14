package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html

ports = [
    "135", "137", "138", "1433", "1434", "20", "21", "22", "23", "25", "3306", "3389", "4333",
    "445", "53", "5432", "5500", "5900"
]

aws_issue[port] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[_]
    port := ports[_]

    ingress.cidr_blocks[_] == "0.0.0.0/0"
    to_number(ingress.from_port) <= to_number(port)
    to_number(ingress.to_port) >= to_number(port)
}

aws_issue[port] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_security_group_rule"
    port := ports[_]

    resource.properties.cidr_blocks[_] == "0.0.0.0/0"
    to_number(resource.properties.from_port) <= to_number(port)
    to_number(resource.properties.to_port) >= to_number(port)
}

aws_issue[port] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[_]
    port := ports[_]

    ingress.ipv6_cidr_blocks[_] == "::/0"
    to_number(ingress.from_port) <= to_number(port)
    to_number(ingress.to_port) >= to_number(port)
}

aws_issue[port] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_security_group_rule"
    port := ports[_]

    resource.properties.ipv6_cidr_blocks[_] == "::/0"
    to_number(resource.properties.from_port) <= to_number(port)
    to_number(resource.properties.to_port) >= to_number(port)
}

aws_issue["all"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_security_group"
    lower(resource.properties.GroupName) == "default"
    resource.properties.ingress[_].ipv6_cidr_blocks[_] == "::/0"
}

aws_issue["all"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_security_group_rule"
    lower(resource.properties.GroupName) == "default"
    resource.properties.ingress[_].ipv6_cidr_blocks[_] == "::/0"
}

aws_issue["all"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_security_group"
    lower(resource.properties.GroupName) == "default"
    resource.properties.ingress[_].cidr_blocks[_] == "0.0.0.0/0"
}

aws_issue["all"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_security_group_rule"
    lower(resource.properties.GroupName) == "default"
    resource.properties.ingress[_].cidr_blocks[_] == "0.0.0.0/0"
}

aws_issue["proto_all"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[_]
    ingress.protocol == "-1"
    ingress.cidr_blocks[_] == "0.0.0.0/0"
}

aws_issue["proto_all"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[_]
    ingress.protocol == "all"
    ingress.cidr_blocks[_] == "0.0.0.0/0"
}

aws_issue["proto_all"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_security_group_rule"
    resource.properties.protocol == "-1"
    resource.properties.cidr_blocks[_] == "0.0.0.0/0"
}

aws_issue["proto_all"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_security_group_rule"
    resource.properties.protocol == "all"
    resource.properties.cidr_blocks[_] == "0.0.0.0/0"
}

aws_issue["proto_all"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[_]
    ingress.protocol == "-1"
    ingress.ipv6_cidr_blocks[_] == "::/0"
}

aws_issue["proto_all"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[_]
    ingress.protocol == "all"
    ingress.ipv6_cidr_blocks[_] == "::/0"
}

aws_issue["proto_all"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_security_group_rule"
    resource.properties.protocol == "-1"
    resource.properties.ipv6_cidr_blocks[_] == "::/0"
}

aws_issue["proto_all"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_security_group_rule"
    resource.properties.protocol == "all"
    resource.properties.ipv6_cidr_blocks[_] == "::/0"
}


#
# PR-AWS-0175-TRF
#

default port_135 = null

port_135 {
    lower(input.json.resources[_].type) == "aws_security_group_rule"
    not aws_issue["135"]
}

port_135 = false {
    aws_issue["135"]
}

port_135_err = "AWS Security Groups allow internet traffic from internet to Windows RPC port (135)" {
        aws_issue["135"]
}

#
# PR-AWS-0165-TRF
#

default port_137 = null

port_137 {
    lower(input.json.resources[_].type) == "aws_security_group_rule"
    not aws_issue["137"]
}

port_137 = false {
    aws_issue["137"]
}

port_137_err = "AWS Security Groups allow internet traffic from internet to NetBIOS port (137)" {
        aws_issue["137"]
}

#
# PR-AWS-0166-TRF
#

default port_138 = null

port_138 {
    lower(input.json.resources[_].type) == "aws_security_group_rule"
    not aws_issue["138"]
}

port_138 = false {
    aws_issue["138"]
}

port_138_err = "AWS Security Groups allow internet traffic from internet to NetBIOS port (138)" {
        aws_issue["138"]
}

#
# PR-AWS-0170-TRF
#

default port_1433 = null

port_1433 {
    lower(input.json.resources[_].type) == "aws_security_group_rule"
    not aws_issue["1433"]
}

port_1433 = false {
    aws_issue["1433"]
}

port_1433_err = "AWS Security Groups allow internet traffic from internet to SQLServer port (1433)" {
    aws_issue["1433"]
}

#
# PR-AWS-0171-TRF
#

default port_1434 = null

port_1434 {
    lower(input.json.resources[_].type) == "aws_security_group_rule"
    not aws_issue["1434"]
}

port_1434 = false {
    aws_issue["1434"]
}

port_1434_err = "AWS Security Groups allow internet traffic from internet to SQLServer port (1434)" {
    aws_issue["1434"]
}

#
# PR-AWS-0162-TRF
#

default port_20 = null

port_20 {
    lower(input.json.resources[_].type) == "aws_security_group_rule"
    not aws_issue["20"]
}

port_20 = false {
    aws_issue["20"]
}

port_20_err = "AWS Security Groups allow internet traffic from internet to FTP-Data port (20)" {
        aws_issue["20"]
}

#
# PR-AWS-0161-TRF
#

default port_21 = null

port_21 {
    lower(input.json.resources[_].type) == "aws_security_group_rule"
    not aws_issue["21"]
}

port_21 = false {
    aws_issue["21"]
}

port_21_err = "AWS Security Groups allow internet traffic from internet to FTP port (21)" {
        aws_issue["21"]
}

#
# PR-AWS-0176-TRF
#

default port_22 = null

port_22 {
    lower(input.json.resources[_].type) == "aws_security_group_rule"
    not aws_issue["22"]
}

port_22 = false {
    aws_issue["22"]
}

port_22_err = "AWS Security Groups allow internet traffic to SSH port (22)" {
        aws_issue["22"]
}

#
# PR-AWS-0172-TRF
#

default port_23 = null

port_23 {
    lower(input.json.resources[_].type) == "aws_security_group_rule"
    not aws_issue["23"]
}

port_23 = false {
    aws_issue["23"]
}

port_23_err = "AWS Security Groups allow internet traffic from internet to Telnet port (23)" {
        aws_issue["23"]
}

#
# PR-AWS-0169-TRF
#

default port_25 = null

port_25 {
    lower(input.json.resources[_].type) == "aws_security_group_rule"
    not aws_issue["25"]
}

port_25 = false {
    aws_issue["25"]
}

port_25_err = "AWS Security Groups allow internet traffic from internet to SMTP port (25)" {
        aws_issue["25"]
}

#
# PR-AWS-0164-TRF
#

default port_3306 = null

port_3306 {
    lower(input.json.resources[_].type) == "aws_security_group_rule"
    not aws_issue["3306"]
}

port_3306 = false {
    aws_issue["3306"]
}

port_3306_err = "AWS Security Groups allow internet traffic from internet to MYSQL port (3306)" {
    aws_issue["3306"]
}

#
# PR-AWS-0168-TRF
#

default port_3389 = null

port_3389 {
    lower(input.json.resources[_].type) == "aws_security_group_rule"
    not aws_issue["3389"]
}

port_3389 = false {
    aws_issue["3389"]
}

port_3389_err = "AWS Security Groups allow internet traffic from internet to RDP port (3389)" {
    aws_issue["3389"]
}

#
# PR-AWS-0163-TRF
#

default port_4333 = null

port_4333 {
    lower(input.json.resources[_].type) == "aws_security_group_rule"
    not aws_issue["4333"]
}

port_4333 = false {
    aws_issue["4333"]
}

port_4333_err = "AWS Security Groups allow internet traffic from internet to MSQL port (4333)" {
    aws_issue["4333"]
}

#
# PR-AWS-0159-TRF
#

default port_445 = null

port_445 {
    lower(input.json.resources[_].type) == "aws_security_group_rule"
    not aws_issue["445"]
}

port_445 = false {
    aws_issue["445"]
}

port_445_err = "AWS Security Groups allow internet traffic from internet to CIFS port (445)" {
        aws_issue["445"]
}

#
# PR-AWS-0160-TRF
#

default port_53 = null

port_53 {
    lower(input.json.resources[_].type) == "aws_security_group_rule"
    not aws_issue["53"]
}

port_53 = false {
    aws_issue["53"]
}

port_53_err = "AWS Security Groups allow internet traffic from internet to DNS port (53)" {
        aws_issue["53"]
}

#
# PR-AWS-0167-TRF
#

default port_5432 = null

port_5432 {
    lower(input.json.resources[_].type) == "aws_security_group_rule"
    not aws_issue["5432"]
}

port_5432 = false {
    aws_issue["5432"]
}

port_5432_err = "AWS Security Groups allow internet traffic from internet to PostgreSQL port (5432)" {
    aws_issue["5432"]
}

#
# PR-AWS-0173-TRF
#

default port_5500 = null

port_5500 {
    lower(input.json.resources[_].type) == "aws_security_group_rule"
    not aws_issue["5500"]
}

port_5500 = false {
    aws_issue["5500"]
}

port_5500_err = "AWS Security Groups allow internet traffic from internet to VNC Listener port (5500)" {
    aws_issue["5500"]
}

#
# PR-AWS-0174-TRF
#

default port_5900 = null

port_5900 {
    lower(input.json.resources[_].type) == "aws_security_group_rule"
    not aws_issue["5900"]
}

port_5900 = false {
    aws_issue["5900"]
}

port_5900_err = "AWS Security Groups allow internet traffic from internet to VNC Server port (5900)" {
    aws_issue["5900"]
}

#
# PR-AWS-0035-TRF
#

default port_all = null

port_all {
    lower(input.json.resources[_].type) == "aws_security_group_rule"
    not aws_issue["all"]
}

port_all = false {
    aws_issue["all"]
}

port_all_err = "AWS Default Security Group does not restrict all traffic" {
    aws_issue["all"]
}

#
# PR-AWS-0178-TRF
#

default port_proto_all = null

port_proto_all {
    lower(input.json.resources[_].type) == "aws_security_group_rule"
    not aws_issue["proto_all"]
}

port_proto_all = false {
    aws_issue["proto_all"]
}

port_proto_all_err = "AWS Security Groups with Inbound rule overly permissive to All Traffic" {
        aws_issue["proto_all"]
}
