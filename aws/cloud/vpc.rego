package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-subnet.html

#
# PR-AWS-CLD-VPC-001
#

default vpc_subnet_autoip = true

vpc_subnet_autoip = false {
    # lower(resource.Type) == "aws::ec2::subnet"
    subnets := input.Subnets[_]
    subnets.MapPublicIpOnLaunch == true
}

vpc_subnet_autoip_err = "AWS VPC subnets should not allow automatic public IP assignment" {
    not vpc_subnet_autoip
}

vpc_subnet_autoip_metadata := {
    "Policy Code": "PR-AWS-CLD-VPC-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS VPC subnets should not allow automatic public IP assignment",
    "Policy Description": "This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateDefaultSubnet.html"
}

#
# PR-AWS-CLD-VPC-002
#

default eip_instance_link = true

eip_instance_link = false {
    # lower(resource.Type) == "aws::ec2::eip"
    addresses = input.Addresses[_]
    lower(addresses.domain) == "vpc"
    not addresses.instanceId
}

eip_instance_link_err = "Ensure all EIP addresses allocated to a VPC are attached related EC2 instances" {
    not eip_instance_link
}

eip_instance_link_metadata := {
    "Policy Code": "PR-AWS-CLD-VPC-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure all EIP addresses allocated to a VPC are attached related EC2 instances",
    "Policy Description": "Ensure that a managed Config rule for AWS Elastic IPs (EIPs) attached to EC2 instances launched inside a VPC is created. Config service tracks changes within your AWS resources configuration and saves the recorded data for security and compliance audits",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Address.html"
}


#
# PR-AWS-CLD-VPC-003
#

default vpc_endpoint_manual_acceptance = true

vpc_endpoint_manual_acceptance = false {
    # lower(resource.Type) == "aws::ec2::vpcendpointservice"
    VpcEndpointConnections := input.VpcEndpointConnections[_]
    lower(VpcEndpointConnections.vpcEndpointState) != "available"
}

vpc_endpoint_manual_acceptance_err = "Ensure VPC endpoint service is configured for manual acceptance" {
    not vpc_endpoint_manual_acceptance
}

vpc_endpoint_manual_acceptance_metadata := {
    "Policy Code": "PR-AWS-CLD-VPC-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure VPC endpoint service is configured for manual acceptance",
    "Policy Description": "AcceptanceRequired Indicates whether requests from service consumers to create an endpoint to your service must be accepted, we recommend you to enable this feature",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_VpcEndpointConnection.html"
}
