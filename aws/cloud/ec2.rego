package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html

#
# PR-AWS-CLD-EC2-001
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
    "Policy Code": "PR-AWS-CLD-EC2-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS EC2 Instance IAM Role not enabled",
    "Policy Description": "AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html"
}

#
# PR-AWS-CLD-EC2-002
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
    "Policy Code": "PR-AWS-CLD-EC2-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS EC2 instance is not configured with VPC",
    "Policy Description": "This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html"
}

#
# PR-AWS-CLD-EC2-003
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
    "Policy Code": "PR-AWS-CLD-EC2-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS EC2 instances with Public IP and associated with Security Groups have Internet Access",
    "Policy Description": "This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html"
}

#
# PR-AWS-CLD-EC2-004
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
    "Policy Code": "PR-AWS-CLD-EC2-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that EC2 instace is EBS Optimized",
    "Policy Description": "Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html#cfn-ec2-instance-ebsoptimized"
}


#
# PR-AWS-CLD-EC2-005
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
    "Policy Code": "PR-AWS-CLD-EC2-005",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure detailed monitoring is enabled for EC2 instances",
    "Policy Description": "Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html#cfn-ec2-instance-monitoring"
}

#
# PR-AWS-CLD-EC2-006
#

default ami_not_infected = true

ami_not_infected = false {
    # lower(resource.Type) == "aws::ec2::instance"
    images := input.Images[_]
    lower(images.Platform) == "windows"
    contains(lower(images.ImageId), "ami-1e542176")
}

ami_not_infected_err = "Ensure Amazon Machine Image (AMI) is not infected with mining malware." {
    not ami_not_infected
}

ami_not_infected_metadata := {
    "Policy Code": "PR-AWS-CLD-EC2-006",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Amazon Machine Image (AMI) is not infected with mining malware.",
    "Policy Description": "Ensure that the ID of the AMI is not infected with mining malware.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_images"
}