package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html


#
# PR-AWS-CLD-SG-001
#

default port_135 = true

port_135 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= 135
    to_number(ingress.ToPort) >= 135
}

port_135 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= 135
    to_number(ingress.ToPort) >= 135
}

port_135_err = "AWS Security Groups allow internet traffic from internet to Windows RPC port (135)" {
    not port_135
}

port_135_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to Windows RPC port (135)",
    "Policy Description": "This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-CLD-SG-002
#

default port_137 = true

port_137 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= 137
    to_number(ingress.ToPort) >= 137
}

port_137 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= 137
    to_number(ingress.ToPort) >= 137
}

port_137_err = "AWS Security Groups allow internet traffic from internet to NetBIOS port (137)" {
    not port_137
}

port_137_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to NetBIOS port (137)",
    "Policy Description": "This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-CLD-SG-003
#

default port_138 = true

port_138 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= 138
    to_number(ingress.ToPort) >= 138
}

port_138 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= 138
    to_number(ingress.ToPort) >= 138
}

port_138_err = "AWS Security Groups allow internet traffic from internet to NetBIOS port (138)" {
    not port_138
}

port_138_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to NetBIOS port (138)",
    "Policy Description": "This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-CLD-SG-004
#

default port_1433 = true

port_1433 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= 1433
    to_number(ingress.ToPort) >= 1433
}

port_1433 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= 1433
    to_number(ingress.ToPort) >= 1433
}

port_1433_err = "AWS Security Groups allow internet traffic from internet to SQLServer port (1433)" {
    not port_1433
}

port_1433_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to SQLServer port (1433)",
    "Policy Description": "This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-CLD-SG-005
#

default port_1434 = true

port_1434 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= 1434
    to_number(ingress.ToPort) >= 1434
}

port_1434 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= 1434
    to_number(ingress.ToPort) >= 1434
}

port_1434_err = "AWS Security Groups allow internet traffic from internet to SQLServer port (1434)" {
    not port_1434
}

port_1434_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-005",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to SQLServer port (1434)",
    "Policy Description": "This policy identifies the security groups which are exposing SQLServer port (1434) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1434) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-CLD-SG-006
#

default port_20 = true

port_20 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= 20
    to_number(ingress.ToPort) >= 20
}

port_20 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= 20
    to_number(ingress.ToPort) >= 20
}

port_20_err = "AWS Security Groups allow internet traffic from internet to FTP-Data port (20)" {
    not port_20
}

port_20_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-006",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to FTP-Data port (20)",
    "Policy Description": "This policy identifies the security groups which are exposing FTP-Data port (20) to the internet. It is recommended that Global permission to access the well known services FTP-Data port (20) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-CLD-SG-007
#

default port_21 = true

port_21 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= 21
    to_number(ingress.ToPort) >= 21
}

port_21 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= 21
    to_number(ingress.ToPort) >= 21
}

port_21_err = "AWS Security Groups allow internet traffic from internet to FTP port (21)" {
    not port_21
}

port_21_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-007",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to FTP port (21)",
    "Policy Description": "This policy identifies the security groups which are exposing FTP port (21) to the internet. It is recommended that Global permission to access the well known services FTP port (21) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-CLD-SG-008
#

default port_22 = true

port_22 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= 22
    to_number(ingress.ToPort) >= 22
}

port_22 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= 22
    to_number(ingress.ToPort) >= 22
}

port_22_err = "AWS Security Groups allow internet traffic to SSH port (22)" {
    not port_22
}

port_22_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-008",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic to SSH port (22)",
    "Policy Description": "This policy identifies AWS Security Groups which do allow inbound traffic on SSH port (22) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-CLD-SG-009
#

default port_23 = true

port_23 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= 23
    to_number(ingress.ToPort) >= 23
}

port_23 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= 23
    to_number(ingress.ToPort) >= 23
}

port_23_err = "AWS Security Groups allow internet traffic from internet to Telnet port (23)" {
    not port_23
}

port_23_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-009",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to Telnet port (23)",
    "Policy Description": "This policy identifies the security groups which are exposing Telnet port (23) to the internet. It is recommended that Global permission to access the well known services Telnet port (23) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-CLD-SG-010
#

default port_25 = true

port_25 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= 25
    to_number(ingress.ToPort) >= 25
}

port_25 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= 25
    to_number(ingress.ToPort) >= 25
}

port_25_err = "AWS Security Groups allow internet traffic from internet to SMTP port (25)" {
    not port_25
}

port_25_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-010",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to SMTP port (25)",
    "Policy Description": "This policy identifies the security groups which are exposing SMTP port (25) to the internet. It is recommended that Global permission to access the well known services SMTP port (25) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-CLD-SG-011
#

default port_3306 = true

port_3306 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= 3306
    to_number(ingress.ToPort) >= 3306
}

port_3306 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= 3306
    to_number(ingress.ToPort) >= 3306
}

port_3306_err = "AWS Security Groups allow internet traffic from internet to MYSQL port (3306)" {
    not port_3306
}

port_3306_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-011",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to MYSQL port (3306)",
    "Policy Description": "This policy identifies the security groups which are exposing MYSQL port (3306) to the internet. It is recommended that Global permission to access the well known services MYSQL port (3306) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-CLD-SG-012
#

default port_3389 = true

port_3389 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= 3389
    to_number(ingress.ToPort) >= 3389
}

port_3389 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= 3389
    to_number(ingress.ToPort) >= 3389
}

port_3389_err = "AWS Security Groups allow internet traffic from internet to RDP port (3389)" {
    not port_3389
}

port_3389_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-012",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to RDP port (3389)",
    "Policy Description": "This policy identifies the security groups which is exposing RDP port (3389) to the internet. Security Groups do not allow inbound traffic on RDP port (3389) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-CLD-SG-013
#

default port_4333 = true

port_4333 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= 4333
    to_number(ingress.ToPort) >= 4333
}

port_4333 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= 4333
    to_number(ingress.ToPort) >= 4333
}

port_4333_err = "AWS Security Groups allow internet traffic from internet to MSQL port (4333)" {
    not port_4333
}

port_4333_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-013",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to MSQL port (4333)",
    "Policy Description": "This policy identifies the security groups which are exposing MSQL port (4333) to the internet. It is recommended that Global permission to access the well known services MSQL port (4333) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-CLD-SG-014
#

default port_445 = true

port_445 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= 445
    to_number(ingress.ToPort) >= 445
}

port_445 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= 445
    to_number(ingress.ToPort) >= 445
}

port_445_err = "AWS Security Groups allow internet traffic from internet to CIFS port (445)" {
    not port_445
}

port_445_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-014",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to CIFS port (445)",
    "Policy Description": "This policy identifies the security groups which are exposing CIFS port (445) to the internet. It is recommended that Global permission to access the well known services CIFS port (445) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-CLD-SG-015
#

default port_53 = true

port_53 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= 53
    to_number(ingress.ToPort) >= 53
}

port_53 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= 53
    to_number(ingress.ToPort) >= 53
}

port_53_err = "AWS Security Groups allow internet traffic from internet to DNS port (53)" {
    not port_53
}

port_53_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-015",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to DNS port (53)",
    "Policy Description": "This policy identifies the security groups which are exposing DNS port (53) to the internet. It is recommended that Global permission to access the well known services DNS port (53) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-CLD-SG-016
#

default port_5432 = true

port_5432 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= 5432
    to_number(ingress.ToPort) >= 5432
}

port_5432 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= 5432
    to_number(ingress.ToPort) >= 5432
}

port_5432_err = "AWS Security Groups allow internet traffic from internet to PostgreSQL port (5432)" {
    not port_5432
}

port_5432_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-016",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to PostgreSQL port (5432)",
    "Policy Description": "This policy identifies the security groups which are exposing PostgreSQL port (5432) to the internet. It is recommended that Global permission to access the well known services PostgreSQL port (5432) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-CLD-SG-017
#

default port_5500 = true

port_5500 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= 5500
    to_number(ingress.ToPort) >= 5500
}

port_5500 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= 5500
    to_number(ingress.ToPort) >= 5500
}

port_5500_err = "AWS Security Groups allow internet traffic from internet to VNC Listener port (5500)" {
    not port_5500
}

port_5500_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-017",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to VNC Listener port (5500)",
    "Policy Description": "This policy identifies the security groups which are exposing VNC Listener port (5500) to the internet. It is recommended that Global permission to access the well known services VNC Listener port (5500) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-CLD-SG-018
#

default port_5900 = true

port_5900 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= 5900
    to_number(ingress.ToPort) >= 5900
}

port_5900 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= 5900
    to_number(ingress.ToPort) >= 5900
}

port_5900_err = "AWS Security Groups allow internet traffic from internet to VNC Server port (5900)" {
    not port_5900
}

port_5900_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-018",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to VNC Server port (5900)",
    "Policy Description": "This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-CLD-SG-019
#

default port_all = true

port_all = false {
    SecurityGroups := input.SecurityGroups[_]
    lower(SecurityGroups.GroupName) == "default"
    ingress := SecurityGroups.IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
}

port_all = false {
    SecurityGroups := input.SecurityGroups[_]
    lower(SecurityGroups.GroupName) == "default"
    ingress := SecurityGroups.IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6 == "::/0"
}

port_all_err = "AWS Default Security Group does not restrict all traffic" {
    not port_all
}

port_all_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-019",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Default Security Group does not restrict all traffic",
    "Policy Description": "This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-CLD-SG-020
#

default port_proto_all = true

port_proto_all = false {
    SecurityGroups := input.SecurityGroups[_]
    lower(SecurityGroups.GroupName) == "default"
    egress := SecurityGroups.IpPermissionsEgress[_]
    egress.IpRanges[_].CidrIp == "0.0.0.0/0"
}

port_proto_all = false {
    SecurityGroups := input.SecurityGroups[_]
    lower(SecurityGroups.GroupName) == "default"
    egress := SecurityGroups.IpPermissionsEgress[_]
    egress.Ipv6Ranges[_].CidrIpv6 == "::/0"
}

port_proto_all_err = "AWS Security Groups with Inbound rule overly permissive to All Traffic" {
    not port_proto_all
}

port_proto_all_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-020",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups with Inbound rule overly permissive to All Traffic",
    "Policy Description": "This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-CLD-SG-021
#

default port_69 = true

port_69 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= 69
    to_number(ingress.ToPort) >= 69
}

port_69 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= 69
    to_number(ingress.ToPort) >= 69
}

port_69_err = "AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)" {
    not port_69
}

port_69_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-021",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)",
    "Policy Description": "This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}


#
# PR-AWS-CLD-SG-022
#

default sg_tag = true

sg_tag = false {
    SecurityGroups := input.SecurityGroups[_]
    count(SecurityGroups.Tags) == 0
}

sg_tag = false {
    # lower(resource.Type) == "aws::ec2::securitygroup"
    SecurityGroups := input.SecurityGroups[_]
    not SecurityGroups.Tags
}

sg_tag_err = "Ensure AWS resources that support tags have Tags" {
    not sg_tag
}

sg_tag_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-022",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS resources that support tags have Tags",
    "Policy Description": "Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html#cfn-ec2-securitygroup-tags"
}


#
# PR-AWS-CLD-SG-023
#

default sg_description_absent = true

sg_description_absent = false {
    # lower(resource.Type) == "aws::ec2::securitygroup"
    ipv6_range := input.SecurityGroups[_].IpPermissions[_].Ipv6Ranges[_]
    not ipv6_range.description
}

sg_description_absent = false {
    # lower(resource.Type) == "aws::ec2::securitygroup"
    ipv6_range := input.SecurityGroups[_].IpPermissions[_].Ipv6Ranges[_]
    count(ipv6_range.description) == 0
}

sg_description_absent = false {
    # lower(resource.Type) == "aws::ec2::securitygroup"
    ip_range := input.SecurityGroups[_].IpPermissions[_].IpRanges[_]
    not ip_range.description
}

sg_description_absent = false {
    # lower(resource.Type) == "aws::ec2::securitygroup"
    ip_range := input.SecurityGroups[_].IpPermissions[_].IpRanges[_]
    count(ip_range.description) == 0
}

sg_description_absent_err = "Ensure every Security Group rule contains a description" {
    not sg_description_absent
}

sg_description_absent_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-023",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure every Security Group rule contains a description",
    "Policy Description": "We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group-rule-1.html#cfn-ec2-security-group-rule-description"
}


#
# PR-AWS-CLD-SG-024
#

default port_9300 = true

port_9300 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= 9300
    to_number(ingress.ToPort) >= 9300
}

port_9300 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= 9300
    to_number(ingress.ToPort) >= 9300
}

port_9300_err = "AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)" {
    not port_9300
}

port_9300_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-024",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)",
    "Policy Description": "This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}


#
# PR-AWS-CLD-SG-025
#

default port_5601 = true

port_5601 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= 5601
    to_number(ingress.ToPort) >= 5601
}

port_5601 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= 5601
    to_number(ingress.ToPort) >= 5601
}

port_5601_err = "AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)" {
    not port_5601
}

port_5601_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-025",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)",
    "Policy Description": "This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}


#
# PR-AWS-CLD-SG-026
#

default port_2379 = true

port_2379 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= 2379
    to_number(ingress.ToPort) >= 2379
}

port_2379 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= 2379
    to_number(ingress.ToPort) >= 2379
}

port_2379_err = "AWS Security Groups allow internet traffic from internet to etcd-client Protocol Port (2379)" {
    not port_2379
}

port_2379_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-026",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to etcd-client Protocol Port (2379)",
    "Policy Description": "This policy identifies the security groups which are exposing etcd-client Protocol Port (2379) to the internet. It is recommended that Global permission to access the well known services etcd-client Protocol Port (2379) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-CLD-SG-027
#

default port_5986 = true

port_5986 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= 5986
    to_number(ingress.ToPort) >= 5986
}

port_5986 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= 5986
    to_number(ingress.ToPort) >= 5986
}

port_5986_err = "AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986)" {
    not port_5986
}

port_5986_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-027",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986)",
    "Policy Description": "This policy identifies the security groups which are exposing WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986) to the internet. It is recommended that Global permission to access the well known services WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}


#
# PR-AWS-CLD-SG-028
#

default port_5985 = true

port_5985 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= 5985
    to_number(ingress.ToPort) >= 5985
}

port_5985 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= 5985
    to_number(ingress.ToPort) >= 5985
}

port_5985_err = "AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985)" {
    not port_5985
}

port_5985_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-028",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985)",
    "Policy Description": "This policy identifies the security groups which are exposing WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985) to the internet. It is recommended that Global permission to access the well known services WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}


#
# PR-AWS-CLD-SG-029
#

default port_1270 = true

port_1270 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= 1270
    to_number(ingress.ToPort) >= 1270
}

port_1270 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    to_number(ingress.FromPort) <= 1270
    to_number(ingress.ToPort) >= 1270
}

port_1270_err = "AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)" {
    not port_1270
}

port_1270_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-029",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)",
    "Policy Description": "This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-CLD-SG-030
#

default db_exposed = true

db_ports := [
    1433, 1521, 3306, 5000, 5432, 5984, 6379, 6380, 8080, 9042, 11211, 27017, 28015, 29015, 50000
]

db_exposed = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    port := db_ports[_]
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

db_exposed = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    port := db_ports[_]
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

db_exposed_err = "Publicly exposed DB Ports" {
    not db_exposed
}

db_exposed_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-030",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Publicly exposed DB Ports",
    "Policy Description": "DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-CLD-SG-031
#

default bitcoin_ports = true

bc_ports := [
    8332, 8333
]

db_exposed = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    port := bc_ports[_]
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

db_exposed = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    port := bc_ports[_]
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

bitcoin_ports_err = "Instance is communicating with ports known to mine Bitcoin" {
    not db_exposed
}

bitcoin_ports_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-031",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Instance is communicating with ports known to mine Bitcoin",
    "Policy Description": "Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-CLD-SG-032
#

default ethereum_ports = true

eth_ports := [
    8545, 30303
]

ethereum_ports = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    port := eth_ports[_]
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

ethereum_ports = false {
    # lower(input.Type) == "aws::ec2::securitygroup"	
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6="::/0"
    port := eth_ports[_]
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

ethereum_ports_err = "Instance is communicating with ports known to mine Ethereum" {
    not ethereum_ports
}

ethereum_ports_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-032",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Instance is communicating with ports known to mine Ethereum",
    "Policy Description": "Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-CLD-SG-033
#

default sg_vpc = true

sg_vpc = false {
    SecurityGroups := input.SecurityGroups[_]
    # lower(resource.Type) == "aws::ec2::securitygroup"
    not SecurityGroups.VpcId
}

sg_vpc = false {
    SecurityGroups := input.SecurityGroups[_]
    # lower(resource.Type) == "aws::ec2::securitygroup"
    not SecurityGroups.VpcId
    count(SecurityGroups.VpcId) == 0
}

sg_vpc_err = "Ensure Security groups has attached to a VPCs" {
    not sg_vpc
}

sg_vpc_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-033",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Security groups has attached to a VPCs",
    "Policy Description": "Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html#cfn-ec2-securitygroup-vpcid"
}

#
# PR-AWS-CLD-SG-034
#

default ec2_instance_has_restricted_access = true

ec2_instance_allowed_protocols := ["http", "https"]

ec2_instance_allowed_ports := [443, 80]

ec2_instance_has_restricted_access = false {
	SecurityRule := input.SecurityGroupRules[_]
	lower(SecurityRule.CidrIpv6) == "::/0"
    not is_secure["ipv6"]
}

is_secure["ipv6"] = true {
    # lower(resource.Type) == "aws::ec2::securitygroup"
    SecurityRule := input.SecurityGroupRules[_]
    lower(SecurityRule.IpProtocol) == ec2_instance_allowed_protocols[_]
    lower(SecurityRule.CidrIpv6) == "::/0"
	SecurityRule.FromPort == ec2_instance_allowed_ports[_]
	SecurityRule.ToPort == ec2_instance_allowed_ports[_]
    SecurityRule.FromPort == SecurityRule.ToPort
}

ec2_instance_has_restricted_access = false {
	SecurityRule := input.SecurityGroupRules[_]
	lower(SecurityRule.CidrIpv4) == "0.0.0.0/0"
    not is_secure["ipv4"]
}

is_secure["ipv4"] = true {
    # lower(resource.Type) == "aws::ec2::securitygroup"
    SecurityRule := input.SecurityGroupRules[_]
    lower(SecurityRule.IpProtocol) == ec2_instance_allowed_protocols[_]
    lower(SecurityRule.CidrIpv4) == "0.0.0.0/0"
	SecurityRule.FromPort == ec2_instance_allowed_ports[_]
	SecurityRule.ToPort == ec2_instance_allowed_ports[_]
    SecurityRule.FromPort == SecurityRule.ToPort
}


ec2_instance_has_restricted_access_err = "Ensure EC2 instance that is not internet reachable with unrestricted access (0.0.0.0/0) other than HTTP/HTTPS port monitoring is enabled for EC2 instances" {
    not ec2_instance_has_restricted_access
}

ec2_instance_has_restricted_access_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-034",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure EC2 instance that is not internet reachable with unrestricted access (0.0.0.0/0) other than HTTP/HTTPS port monitoring is enabled for EC2 instances",
    "Policy Description": "Ensure restrict traffic from unknown IP addresses and limit the access to known hosts, services, or specific entities. NOTE: We are excluding the HTTP-80 and HTTPs-443 web ports as these are Internet-facing ports with legitimate traffic.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_security_group_rules"
}