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


#
# PR-AWS-CLD-VPC-004
# aws::ec2::vpc

default default_vpc_not_used = true

default_vpc_not_used = false {
    vpc := input.Vpcs[_]
    vpc.IsDefault == true
    lower(vpc.State) == "available"
}

default_vpc_not_used_err = "Ensure default VPC is not being used." {
    not default_vpc_not_used
}

default_vpc_not_used_metadata := {
    "Policy Code": "PR-AWS-CLD-VPC-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure default VPC is not being used.",
    "Policy Description": "It is to check that only firm managed VPC is used and not the default one.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpcs"
}


#
# PR-AWS-CLD-VPC-005
# aws::ec2::vpcpeeringconnection

default vpc_peering_connection_inactive = true

vpc_peering_connection_inactive = false {
    VpcPeeringConnection := input.VpcPeeringConnections[_]
    lower(VpcPeeringConnection.Status.Code) == "active"
}

vpc_peering_connection_inactive_err = "Ensure VPC peering connection is not active." {
    not vpc_peering_connection_inactive
}

vpc_peering_connection_inactive_metadata := {
    "Policy Code": "PR-AWS-CLD-VPC-005",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure VPC peering connection is not active.",
    "Policy Description": "It checks of VPC peering is allowed between VPCs. VPC peering is not encrypted and not allowed to be used in GS environment.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpc_peering_connections"
}


#
# PR-AWS-CLD-VPC-006
# aws::ec2::vpcendpoint

default vpc_policy_not_overly_permissive = true

vpc_policy_not_overly_permissive = false {
    VpcEndpoint := input.VpcEndpoints[_]
    statement := VpcEndpoint.PolicyDocument.Statement[i]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
    contains(lower(statement.Action), "*")
    not statement.Condition
}

vpc_policy_not_overly_permissive = false {
    VpcEndpoint := input.VpcEndpoints[_]
    statement := VpcEndpoint.PolicyDocument.Statement[i]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
    contains(lower(statement.Action[_]), "*")
    not statement.Condition
}

vpc_policy_not_overly_permissive = false {
    VpcEndpoint := input.VpcEndpoints[_]
    statement := VpcEndpoint.PolicyDocument.Statement[i]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
    contains(lower(statement.Action), "*")
    not statement.Condition
}

vpc_policy_not_overly_permissive = false {
    VpcEndpoint := input.VpcEndpoints[_]
    statement := VpcEndpoint.PolicyDocument.Statement[i]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
    contains(lower(statement.Action[_]), "*")
    not statement.Condition
}

vpc_policy_not_overly_permissive = false {
    VpcEndpoint := input.VpcEndpoints[_]
    statement := VpcEndpoint.PolicyDocument.Statement[i]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[_] = "*"
    contains(lower(statement.Action), "*")
    not statement.Condition
}

vpc_policy_not_overly_permissive = false {
    VpcEndpoint := input.VpcEndpoints[_]
    statement := VpcEndpoint.PolicyDocument.Statement[i]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[_] = "*"
    contains(lower(statement.Action[_]), "*")
    not statement.Condition
}

vpc_policy_not_overly_permissive_err = "Ensure AWS VPC endpoint policy is not overly permissive." {
    not vpc_policy_not_overly_permissive
}

vpc_policy_not_overly_permissive_metadata := {
    "Policy Code": "PR-AWS-CLD-VPC-006",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS VPC endpoint policy is not overly permissive.",
    "Policy Description": "It identifies VPC endpoints that have a VPC endpoint (VPCE) policy that is overly permissive. When the Principal element value is set to '*' within the access policy, the VPC endpoint allows full access to any IAM user or service within the VPC using credentials from any AWS accounts. It is highly recommended to have the least privileged VPCE policy to protect the data leakage and unauthorized access. For more details: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-endpoints-access.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpc_endpoints"
}