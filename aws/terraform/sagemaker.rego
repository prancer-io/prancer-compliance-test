package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sagemaker-notebookinstance.html
#
# PR-AWS-0247-TRF
#

default sagemaker_encryption_kms = null

aws_issue["sagemaker_encryption_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_sagemaker_notebook_instance"
    not resource.properties.kms_key_id
}

aws_issue["sagemaker_encryption_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_sagemaker_notebook_instance"
    count(resource.properties.kms_key_id) == 0
}

sagemaker_encryption_kms {
    lower(input.resources[i].type) == "aws_sagemaker_notebook_instance"
    not aws_issue["sagemaker_encryption_kms"]
}

sagemaker_encryption_kms = false {
    aws_issue["sagemaker_encryption_kms"]
}

sagemaker_encryption_kms_err = "AWS SageMaker notebook instance not configured with data encryption at rest using KMS key" {
    aws_issue["sagemaker_encryption_kms"]
}

sagemaker_encryption_kms_metadata := {
    "Policy Code": "PR-AWS-0247-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS SageMaker notebook instance not configured with data encryption at rest using KMS key",
    "Policy Description": "This policy identifies SageMaker notebook instances that are not configured with data encryption at rest using the AWS managed KMS key. It is recommended to implement encryption at rest in order to protect data from unauthorized entities.\n\nFor more details:\nhttps://docs.aws.amazon.com/sagemaker/latest/dg/encryption-at-rest.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sagemaker-notebookinstance.html"
}

#
# PR-AWS-0248-TRF
#

default sagemaker_rootaccess_enabled = null

aws_issue["sagemaker_rootaccess_enabled"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_sagemaker_notebook_instance"
    lower(resource.properties.root_access) == "enabled"
}

aws_issue["sagemaker_rootaccess_enabled"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_sagemaker_notebook_instance"
    not resource.properties.root_access
}

sagemaker_rootaccess_enabled {
    lower(input.resources[i].type) == "aws_sagemaker_notebook_instance"
    not aws_issue["sagemaker_rootaccess_enabled"]
}

sagemaker_rootaccess_enabled = false {
    aws_issue["sagemaker_rootaccess_enabled"]
}

sagemaker_rootaccess_enabled_err = "AWS SageMaker notebook instance with root access enabled" {
    aws_issue["sagemaker_rootaccess_enabled"]
}

sagemaker_rootaccess_enabled_metadata := {
    "Policy Code": "PR-AWS-0248-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS SageMaker notebook instance with root access enabled",
    "Policy Description": "This policy identifies the SageMaker notebook instances which are enabled with root access. Root access means having administrator privileges, users with root access can access and edit all files on the compute instance, including system-critical files. Removing root access prevents notebook users from deleting system-level software, installing new software, and modifying essential environment components.\nNOTE: Lifecycle configurations need root access to be able to set up a notebook instance. Because of this, lifecycle configurations associated with a notebook instance always run with root access even if you disable root access for users.\n\nFor more details:\nhttps://docs.aws.amazon.com/sagemaker/latest/dg/nbi-root-access.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sagemaker-notebookinstance.html"
}


#
# PR-AWS-0249-TRF
#

default sagemaker_direct_internet_access_enabled = null

aws_issue["sagemaker_direct_internet_access_enabled"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_sagemaker_notebook_instance"
    lower(resource.properties.direct_internet_access) == "enabled"
}

aws_issue["sagemaker_direct_internet_access_enabled"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_sagemaker_notebook_instance"
    not resource.properties.direct_internet_access
}

sagemaker_direct_internet_access_enabled {
    lower(input.resources[i].type) == "aws_sagemaker_notebook_instance"
    not aws_issue["sagemaker_direct_internet_access_enabled"]
}

sagemaker_direct_internet_access_enabled = false {
    aws_issue["sagemaker_direct_internet_access_enabled"]
}

sagemaker_direct_internet_access_enabled_err = "AWS SageMaker notebook instance configured with direct internet access feature" {
    aws_issue["sagemaker_direct_internet_access_enabled"]
}

sagemaker_direct_internet_access_enabled_metadata := {
    "Policy Code": "PR-AWS-0249-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS SageMaker notebook instance configured with direct internet access feature",
    "Policy Description": "This policy identifies SageMaker notebook instances that are configured with direct internet access feature. If AWS SageMaker notebook instances are configured with direct internet access feature, any machine outside the VPC can establish a connection to these instances, which provides an additional avenue for unauthorized access to data and the opportunity for malicious activity.\n\nFor more details:\nhttps://docs.aws.amazon.com/sagemaker/latest/dg/appendix-notebook-and-internet-access.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sagemaker-notebookinstance.html"
}


#
# PR-AWS-0250-TRF
#

default sagemaker_vpc = null

aws_issue["sagemaker_vpc"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_sagemaker_notebook_instance"
    count(resource.properties.subnet_id) == 0
}

aws_issue["sagemaker_vpc"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_sagemaker_notebook_instance"
    not resource.properties.subnet_id
}

sagemaker_vpc {
    lower(input.resources[i].type) == "aws_sagemaker_notebook_instance"
    not aws_issue["sagemaker_vpc"]
}

sagemaker_vpc = false {
    aws_issue["sagemaker_vpc"]
}

sagemaker_vpc_err = "AWS SageMaker notebook instance is not placed in VPC" {
    aws_issue["sagemaker_vpc"]
}

sagemaker_vpc_metadata := {
    "Policy Code": "PR-AWS-0250-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS SageMaker notebook instance is not placed in VPC",
    "Policy Description": "This policy identifies SageMaker notebook instances that are not placed inside a VPC. It is recommended to place your SageMaker inside VPC so that VPC-only resources able to access your SageMaker data, which cannot be accessed outside a VPC network.\n\nFor more details:\nhttps://docs.aws.amazon.com/sagemaker/latest/dg/process-vpc.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sagemaker-notebookinstance.html"
}
