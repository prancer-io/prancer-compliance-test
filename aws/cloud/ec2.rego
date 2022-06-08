package rule

available_true_choices := ["true", true]

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

default ec2_deletion_termination = true

ec2_deletion_termination = false {
    # lower(resource.Type) == "aws::ec2::instance"
    Reservations := input.Reservations[_]
    Instances := Reservations.Instances[_]
    BlockDeviceMappings := Instances.BlockDeviceMappings[_]
    has_property(BlockDeviceMappings.Ebs, "DeleteOnTermination")
    BlockDeviceMappings.Ebs.DeleteOnTermination == available_true_choices[_]
    NetworkInterfaces := Instances.NetworkInterfaces[_]
    has_property(NetworkInterfaces.Attachment, "DeleteOnTermination")
    NetworkInterfaces.Attachment.DeleteOnTermination == available_true_choices[_]
}

ec2_deletion_termination = false {
    # lower(resource.Type) == "aws::ec2::instance"
    Reservations := input.Reservations[_]
    Instances := Reservations.Instances[_]
    BlockDeviceMappings := Instances.BlockDeviceMappings[_]
    has_property(BlockDeviceMappings.Ebs, "DeleteOnTermination")
    BlockDeviceMappings.Ebs.DeleteOnTermination == available_true_choices[_]
    NetworkInterfaces := Instances.NetworkInterfaces[_]
    not has_property(NetworkInterfaces.Attachment, "DeleteOnTermination")
}


ec2_deletion_termination = false {
    # lower(resource.Type) == "aws::ec2::instance"
    Reservations := input.Reservations[_]
    Instances := Reservations.Instances[_]
    BlockDeviceMappings := Instances.BlockDeviceMappings[_]
    not has_property(BlockDeviceMappings.Ebs, "DeleteOnTermination")
    NetworkInterfaces := Instances.NetworkInterfaces[_]
    has_property(NetworkInterfaces.Attachment, "DeleteOnTermination")
    NetworkInterfaces.Attachment.DeleteOnTermination == available_true_choices[_]
}

ec2_deletion_termination = false {
    # lower(resource.Type) == "aws::ec2::instance"
    Reservations := input.Reservations[_]
    Instances := Reservations.Instances[_]
    BlockDeviceMappings := Instances.BlockDeviceMappings[_]
    not has_property(BlockDeviceMappings.Ebs, "DeleteOnTermination")
    NetworkInterfaces := Instances.NetworkInterfaces[_]
    not has_property(NetworkInterfaces.Attachment, "DeleteOnTermination")
}

ec2_deletion_termination_err = "Ensure AWS EC2 EBS and Network components' deletion protection is enabled" {
    not ec2_deletion_termination
}

ec2_deletion_termination_metadata := {
    "Policy Code": "PR-AWS-CLD-EC2-006",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS EC2 EBS and Network components' deletion protection is enabled",
    "Policy Description": "This checks if the EBS volumes are configured to be terminated along with the EC2 instance",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-instances.html"
}

#
# PR-AWS-CLD-EC2-007
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
    "Policy Code": "PR-AWS-CLD-EC2-007",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Amazon Machine Image (AMI) is not infected with mining malware.",
    "Policy Description": "This policy identifies Amazon Machine Images (AMIs) that are infected with mining malware. As per research, AWS Community AMI Windows 2008 hosted by an unverified vendor containing malicious code running an unidentified crypto (Monero) miner. It is recommended to delete such AMIs to protect from malicious activity and attack blast.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_images"
}

#
# PR-AWS-CLD-EC2-008
#

default ebs_snapshot_public_access = true

ebs_snapshot_public_access = false {
    # lower(resource.Type) == "aws::ec2::instance"
    CreateVolumePermissions := input.CreateVolumePermissions[_]
    lower(CreateVolumePermissions.Group) == "all"
}

ebs_snapshot_public_access_err = "Ensure AWS EBS snapshots are not accessible to public" {
    not ebs_snapshot_public_access
}

ebs_snapshot_public_access_metadata := {
    "Policy Code": "PR-AWS-CLD-EC2-008",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS EBS snapshots are not accessible to the public",
    "Policy Description": "This policy identifies EC2 EBS snapshots are accessible to the public. Amazon Elastic Block Store (Amazon EBS) provides persistent block storage volumes with Amazon EC2 instances in the AWS Cloud. If EBS snapshots are inadvertently shared to the public, any unauthorized user with AWS console access can gain access to the snapshots and gain access to sensitive data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_images"
}

#
# PR-AWS-CLD-EC2-009
#

default ami_is_not_publicly_accessible = true

ami_is_not_publicly_accessible = false {
    # lower(resource.Type) == "aws::ec2::instance"
    images := input.Images[_]
    lower(images.Public) == available_true_choices[_]
    not images.ImageOwnerAlias
}

ami_is_not_publicly_accessible_err = "Ensure AWS Amazon Machine Image (AMI) is not publicly accessible." {
    not ami_is_not_publicly_accessible
}

ami_is_not_publicly_accessible_metadata := {
    "Policy Code": "PR-AWS-CLD-EC2-009",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS Amazon Machine Image (AMI) is not publicly accessible.",
    "Policy Description": "It identifies AWS AMIs which are owned by the AWS account and are accessible to the public. Amazon Machine Image (AMI) provides information to launch an instance in the cloud. The AMIs may contain proprietary customer information and should be accessible only to authorized internal users.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_images"
}
