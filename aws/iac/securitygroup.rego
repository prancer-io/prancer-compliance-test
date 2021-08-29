package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html

ports = [
    "135", "137", "138", "1433", "1434", "20", "21", "22", "23", "25", "3306", "3389", "4333",
    "445", "53", "5432", "5500", "5900", "69"
]

aws_issue[port] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::securitygroup"
    ingress := resource.Properties.SecurityGroupIngress[_]
    port := ports[_]

    ingress.CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= to_number(port)
    to_number(ingress.ToPort) >= to_number(port)
}

aws_issue[port] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::securitygroup"
    ingress := resource.Properties.SecurityGroupIngress[_]
    port := ports[_]

    ingress.CidrIpv6 == "::/0"
    to_number(ingress.FromPort) <= to_number(port)
    to_number(ingress.ToPort) >= to_number(port)
}

aws_issue["all"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::securitygroup"
    lower(resource.Properties.GroupName) == "default"
    resource.Properties.SecurityGroupIngress[_].CidrIpv6 == "::/0"
}

aws_issue["all"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::securitygroup"
    lower(resource.Properties.GroupName) == "default"
    resource.Properties.SecurityGroupIngress[_].CidrIp == "0.0.0.0/0"
}

aws_issue["proto_all"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::securitygroup"
    lower(resource.Properties.GroupName) == "default"
    ingress := resource.Properties.SecurityGroupEgress[_]
    ingress.CidrIp == "0.0.0.0/0"
}

aws_issue["proto_all"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::securitygroup"
    lower(resource.Properties.GroupName) == "default"
    ingress := resource.Properties.SecurityGroupEgress[_]
    ingress.CidrIpv6 == "::/0"
}

#
# PR-AWS-0175-CFR
#

default port_135 = null

port_135 {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["135"]
}

port_135 = false {
    aws_issue["135"]
}

port_135_err = "AWS Security Groups allow internet traffic from internet to Windows RPC port (135)" {
        aws_issue["135"]
}

port_135_metadata := {
    "Policy Code": "PR-AWS-0175-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to Windows RPC port (135)",
    "Policy Description": "This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-0165-CFR
#

default port_137 = null

port_137 {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["137"]
}

port_137 = false {
    aws_issue["137"]
}

port_137_err = "AWS Security Groups allow internet traffic from internet to NetBIOS port (137)" {
        aws_issue["137"]
}

port_137_metadata := {
    "Policy Code": "PR-AWS-0165-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to NetBIOS port (137)",
    "Policy Description": "This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-0166-CFR
#

default port_138 = null

port_138 {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["138"]
}

port_138 = false {
    aws_issue["138"]
}

port_138_err = "AWS Security Groups allow internet traffic from internet to NetBIOS port (138)" {
        aws_issue["138"]
}

port_138_metadata := {
    "Policy Code": "PR-AWS-0166-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to NetBIOS port (138)",
    "Policy Description": "This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-0170-CFR
#

default port_1433 = null

port_1433 {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["1433"]
}

port_1433 = false {
    aws_issue["1433"]
}

port_1433_err = "AWS Security Groups allow internet traffic from internet to SQLServer port (1433)" {
    aws_issue["1433"]
}

port_1433_metadata := {
    "Policy Code": "PR-AWS-0170-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to SQLServer port (1433)",
    "Policy Description": "This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-0171-CFR
#

default port_1434 = null

port_1434 {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["1434"]
}

port_1434 = false {
    aws_issue["1434"]
}

port_1434_err = "AWS Security Groups allow internet traffic from internet to SQLServer port (1434)" {
    aws_issue["1434"]
}

port_1434_metadata := {
    "Policy Code": "PR-AWS-0171-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to SQLServer port (1434)",
    "Policy Description": "This policy identifies the security groups which are exposing SQLServer port (1434) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1434) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-0162-CFR
#

default port_20 = null

port_20 {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["20"]
}

port_20 = false {
    aws_issue["20"]
}

port_20_err = "AWS Security Groups allow internet traffic from internet to FTP-Data port (20)" {
        aws_issue["20"]
}

port_20_metadata := {
    "Policy Code": "PR-AWS-0162-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to FTP-Data port (20)",
    "Policy Description": "This policy identifies the security groups which are exposing FTP-Data port (20) to the internet. It is recommended that Global permission to access the well known services FTP-Data port (20) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-0161-CFR
#

default port_21 = null

port_21 {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["21"]
}

port_21 = false {
    aws_issue["21"]
}

port_21_err = "AWS Security Groups allow internet traffic from internet to FTP port (21)" {
        aws_issue["21"]
}

port_21_metadata := {
    "Policy Code": "PR-AWS-0161-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to FTP port (21)",
    "Policy Description": "This policy identifies the security groups which are exposing FTP port (21) to the internet. It is recommended that Global permission to access the well known services FTP port (21) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-0176-CFR
#

default port_22 = null

port_22 {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["22"]
}

port_22 = false {
    aws_issue["22"]
}

port_22_err = "AWS Security Groups allow internet traffic to SSH port (22)" {
        aws_issue["22"]
}

port_22_metadata := {
    "Policy Code": "PR-AWS-0176-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Security Groups allow internet traffic to SSH port (22)",
    "Policy Description": "This policy identifies AWS Security Groups which do allow inbound traffic on SSH port (22) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-0172-CFR
#

default port_23 = null

port_23 {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["23"]
}

port_23 = false {
    aws_issue["23"]
}

port_23_err = "AWS Security Groups allow internet traffic from internet to Telnet port (23)" {
        aws_issue["23"]
}

port_23_metadata := {
    "Policy Code": "PR-AWS-0172-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to Telnet port (23)",
    "Policy Description": "This policy identifies the security groups which are exposing Telnet port (23) to the internet. It is recommended that Global permission to access the well known services Telnet port (23) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-0169-CFR
#

default port_25 = null

port_25 {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["25"]
}

port_25 = false {
    aws_issue["25"]
}

port_25_err = "AWS Security Groups allow internet traffic from internet to SMTP port (25)" {
        aws_issue["25"]
}

port_25_metadata := {
    "Policy Code": "PR-AWS-0169-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to SMTP port (25)",
    "Policy Description": "This policy identifies the security groups which are exposing SMTP port (25) to the internet. It is recommended that Global permission to access the well known services SMTP port (25) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-0164-CFR
#

default port_3306 = null

port_3306 {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["3306"]
}

port_3306 = false {
    aws_issue["3306"]
}

port_3306_err = "AWS Security Groups allow internet traffic from internet to MYSQL port (3306)" {
    aws_issue["3306"]
}

port_3306_metadata := {
    "Policy Code": "PR-AWS-0164-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to MYSQL port (3306)",
    "Policy Description": "This policy identifies the security groups which are exposing MYSQL port (3306) to the internet. It is recommended that Global permission to access the well known services MYSQL port (3306) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-0168-CFR
#

default port_3389 = null

port_3389 {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["3389"]
}

port_3389 = false {
    aws_issue["3389"]
}

port_3389_err = "AWS Security Groups allow internet traffic from internet to RDP port (3389)" {
    aws_issue["3389"]
}

port_3389_metadata := {
    "Policy Code": "PR-AWS-0168-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to RDP port (3389)",
    "Policy Description": "This policy identifies the security groups which is exposing RDP port (3389) to the internet. Security Groups do not allow inbound traffic on RDP port (3389) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-0163-CFR
#

default port_4333 = null

port_4333 {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["4333"]
}

port_4333 = false {
    aws_issue["4333"]
}

port_4333_err = "AWS Security Groups allow internet traffic from internet to MSQL port (4333)" {
    aws_issue["4333"]
}

port_4333_metadata := {
    "Policy Code": "PR-AWS-0163-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to MSQL port (4333)",
    "Policy Description": "This policy identifies the security groups which are exposing MSQL port (4333) to the internet. It is recommended that Global permission to access the well known services MSQL port (4333) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-0159-CFR
#

default port_445 = null

port_445 {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["445"]
}

port_445 = false {
    aws_issue["445"]
}

port_445_err = "AWS Security Groups allow internet traffic from internet to CIFS port (445)" {
        aws_issue["445"]
}

port_445_metadata := {
    "Policy Code": "PR-AWS-0159-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to CIFS port (445)",
    "Policy Description": "This policy identifies the security groups which are exposing CIFS port (445) to the internet. It is recommended that Global permission to access the well known services CIFS port (445) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-0160-CFR
#

default port_53 = null

port_53 {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["53"]
}

port_53 = false {
    aws_issue["53"]
}

port_53_err = "AWS Security Groups allow internet traffic from internet to DNS port (53)" {
        aws_issue["53"]
}

port_53_metadata := {
    "Policy Code": "PR-AWS-0160-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to DNS port (53)",
    "Policy Description": "This policy identifies the security groups which are exposing DNS port (53) to the internet. It is recommended that Global permission to access the well known services DNS port (53) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-0167-CFR
#

default port_5432 = null

port_5432 {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["5432"]
}

port_5432 = false {
    aws_issue["5432"]
}

port_5432_err = "AWS Security Groups allow internet traffic from internet to PostgreSQL port (5432)" {
    aws_issue["5432"]
}

port_5432_metadata := {
    "Policy Code": "PR-AWS-0167-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to PostgreSQL port (5432)",
    "Policy Description": "This policy identifies the security groups which are exposing PostgreSQL port (5432) to the internet. It is recommended that Global permission to access the well known services PostgreSQL port (5432) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-0173-CFR
#

default port_5500 = null

port_5500 {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["5500"]
}

port_5500 = false {
    aws_issue["5500"]
}

port_5500_err = "AWS Security Groups allow internet traffic from internet to VNC Listener port (5500)" {
    aws_issue["5500"]
}

port_5500_metadata := {
    "Policy Code": "PR-AWS-0173-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to VNC Listener port (5500)",
    "Policy Description": "This policy identifies the security groups which are exposing VNC Listener port (5500) to the internet. It is recommended that Global permission to access the well known services VNC Listener port (5500) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-0174-CFR
#

default port_5900 = null

port_5900 {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["5900"]
}

port_5900 = false {
    aws_issue["5900"]
}

port_5900_err = "AWS Security Groups allow internet traffic from internet to VNC Server port (5900)" {
    aws_issue["5900"]
}

port_5900_metadata := {
    "Policy Code": "PR-AWS-0174-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to VNC Server port (5900)",
    "Policy Description": "This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-0035-CFR
#

default port_all = null

port_all {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["all"]
}

port_all = false {
    aws_issue["all"]
}

port_all_err = "AWS Default Security Group does not restrict all traffic" {
    aws_issue["all"]
}

port_all_metadata := {
    "Policy Code": "PR-AWS-0035-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Default Security Group does not restrict all traffic",
    "Policy Description": "This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-0178-CFR
#

default port_proto_all = null

port_proto_all {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["proto_all"]
}

port_proto_all = false {
    aws_issue["proto_all"]
}

port_proto_all_err = "AWS Security Groups with Inbound rule overly permissive to All Traffic" {
        aws_issue["proto_all"]
}

port_proto_all_metadata := {
    "Policy Code": "PR-AWS-0178-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Security Groups with Inbound rule overly permissive to All Traffic",
    "Policy Description": "This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-0251-CFR
#

default port_69 = null

port_69 {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["69"]
}

port_69 = false {
    aws_issue["69"]
}

port_69_err = "AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)" {
    aws_issue["69"]
}

port_69_metadata := {
    "Policy Code": "PR-AWS-0251-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)",
    "Policy Description": "This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}


#
# PR-AWS-0260-CFR
#

default sg_tag = null

aws_issue["sg_tag"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::securitygroup"
    count(resource.Properties.Tags) == 0
}

aws_issue["sg_tag"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::securitygroup"
    not resource.Properties.Tags
}

sg_tag {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["sg_tag"]
}

sg_tag = false {
    aws_issue["sg_tag"]
}

sg_tag_err = "Ensure AWS resources that support tags have Tags" {
    aws_issue["sg_tag"]
}

sg_tag_metadata := {
    "Policy Code": "PR-AWS-0260-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS resources that support tags have Tags",
    "Policy Description": "Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html#cfn-ec2-securitygroup-tags"
}
