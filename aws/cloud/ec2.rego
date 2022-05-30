package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html

#
# PR-AWS-CFR-EC2-001
#

default ec2_iam_role = true

ec2_iam_role = false {
    # lower(resource.Type) == "aws::ec2::instance"
    Reservations := input.Reservations[_]
    Instances := Reservations.Instances[_]
    not Instances.IamInstanceProfile
}

ec2_iam_role = false {
    # lower(resource.Type) == "aws::ec2::instance"
    Reservations := input.Reservations[_]
    Instances := Reservations.Instances[_]
    not startswith(lower(Instances.IamInstanceProfile), "arn:")
}

ec2_iam_role_err = "AWS EC2 Instance IAM Role not enabled" {
    not ec2_iam_role
}

ec2_iam_role_metadata := {
    "Policy Code": "PR-AWS-CFR-EC2-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS EC2 Instance IAM Role not enabled",
    "Policy Description": "AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html"
}

#
# PR-AWS-CFR-EC2-002
#

default ec2_no_vpc = true

ec2_no_vpc = false {
    # lower(resource.Type) == "aws::ec2::instance"
    Reservations := input.Reservations[_]
    Instances := Reservations.Instances[_]
    not Instances.SubnetId
    count([c | Instances.NetworkInterfaces[_].SubnetId; c := 1]) == 0
}

ec2_no_vpc_err = "AWS EC2 instance is not configured with VPC" {
    not ec2_no_vpc
}

ec2_no_vpc_metadata := {
    "Policy Code": "PR-AWS-CFR-EC2-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS EC2 instance is not configured with VPC",
    "Policy Description": "This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html"
}

#
# PR-AWS-CFR-EC2-003
#

default ec2_public_ip = true

ec2_public_ip = false {
    # lower(resource.Type) == "aws::ec2::instance"
    Reservations := input.Reservations[_]
    Instances := Reservations.Instances[_]
    NetworkInterfaces := Instances.NetworkInterfaces[j]
    not has_property(NetworkInterfaces, "AssociatePublicIpAddress")
}

ec2_public_ip = false {
    # lower(resource.Type) == "aws::ec2::instance"
    Reservations := input.Reservations[_]
    Instances := Reservations.Instances[_]
    Instances.NetworkInterfaces[j].AssociatePublicIpAddress == true
    lower(Instances.SecurityGroups[k]) == "default"
}

ec2_public_ip_err = "AWS EC2 instances with Public IP and associated with Security Groups have Internet Access" {
    not ec2_public_ip
}

ec2_public_ip_metadata := {
    "Policy Code": "PR-AWS-CFR-EC2-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS EC2 instances with Public IP and associated with Security Groups have Internet Access",
    "Policy Description": "This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html"
}

#
# PR-AWS-CFR-EC2-004
#

default ec2_ebs_optimized = true

ec2_ebs_optimized = false {
    # lower(resource.Type) == "aws::ec2::instance"
    Reservations := input.Reservations[_]
    Instances := Reservations.Instances[_]
    not Instances.EbsOptimized
}

ec2_ebs_optimized_err = "Ensure that EC2 instace is EBS Optimized" {
    not ec2_ebs_optimized
}

ec2_ebs_optimized_metadata := {
    "Policy Code": "PR-AWS-CFR-EC2-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure that EC2 instace is EBS Optimized",
    "Policy Description": "Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html#cfn-ec2-instance-ebsoptimized"
}


#
# PR-AWS-CFR-EC2-005
#

default ec2_monitoring = true

ec2_monitoring = false {
    # lower(resource.Type) == "aws::ec2::instance"
    Reservations := input.Reservations[_]
    Instances := Reservations.Instances[_]
    not Instances.Monitoring
}

ec2_monitoring = false {
    # lower(resource.Type) == "aws::ec2::instance"
    Reservations := input.Reservations[_]
    Instances := Reservations.Instances[_]
    lower(Instances.Monitoring.State) != "enabled"
}

ec2_monitoring_err = "Ensure detailed monitoring is enabled for EC2 instances" {
    not ec2_monitoring
}

ec2_monitoring_metadata := {
    "Policy Code": "PR-AWS-CFR-EC2-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure detailed monitoring is enabled for EC2 instances",
    "Policy Description": "Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html#cfn-ec2-instance-monitoring"
}

#
# PR-AWS-CFR-EC2-006
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
    # lower(resource.Type) == "aws::ec2::instance"
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
    # lower(resource.Type) == "aws::ec2::instance"
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
    "Policy Code": "PR-AWS-CFR-EC2-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure EC2 instance that is not internet reachable with unrestricted access (0.0.0.0/0) other than HTTP/HTTPS port monitoring is enabled for EC2 instances",
    "Policy Description": "Ensure restrict traffic from unknown IP addresses and limit the access to known hosts, services, or specific entities. NOTE: We are excluding the HTTP-80 and HTTPs-443 web ports as these are Internet-facing ports with legitimate traffic.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_security_group_rules"
}