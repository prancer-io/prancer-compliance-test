package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sagemaker-notebookinstance.html

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

#
# PR-AWS-CLD-SGM-001
#

default sagemaker_encryption_kms = true

sagemaker_encryption_kms = false {
    # lower(resource.Type) == "aws::sagemaker::notebookinstance"
    not input.KmsKeyId
}

sagemaker_encryption_kms = false {
    # lower(resource.Type) == "aws::sagemaker::notebookinstance"
    count(input.KmsKeyId) == 0
}

sagemaker_encryption_kms_err = "AWS SageMaker notebook instance not configured with data encryption at rest using KMS key" {
    not sagemaker_encryption_kms
}

sagemaker_encryption_kms_metadata := {
    "Policy Code": "PR-AWS-CLD-SGM-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS SageMaker notebook instance not configured with data encryption at rest using KMS key",
    "Policy Description": "This policy identifies SageMaker notebook instances that are not configured with data encryption at rest using the AWS managed KMS key. It is recommended to implement encryption at rest in order to protect data from unauthorized entities.\n\nFor more details:\nhttps://docs.aws.amazon.com/sagemaker/latest/dg/encryption-at-rest.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sagemaker-notebookinstance.html"
}

#
# PR-AWS-CLD-SGM-002
#

default sagemaker_rootaccess_enabled = true

sagemaker_rootaccess_enabled = false {
    # lower(resource.Type) == "aws::sagemaker::notebookinstance"
    lower(input.RootAccess) == "enabled"
}

sagemaker_rootaccess_enabled = false {
    # lower(resource.Type) == "aws::sagemaker::notebookinstance"
    not input.RootAccess
}

sagemaker_rootaccess_enabled_err = "AWS SageMaker notebook instance with root access enabled" {
    not sagemaker_rootaccess_enabled
}

sagemaker_rootaccess_enabled_metadata := {
    "Policy Code": "PR-AWS-CLD-SGM-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS SageMaker notebook instance with root access enabled",
    "Policy Description": "This policy identifies the SageMaker notebook instances which are enabled with root access. Root access means having administrator privileges, users with root access can access and edit all files on the compute instance, including system-critical files. Removing root access prevents notebook users from deleting system-level software, installing new software, and modifying essential environment components.\nNOTE: Lifecycle configurations need root access to be able to set up a notebook instance. Because of this, lifecycle configurations associated with a notebook instance always run with root access even if you disable root access for users.\n\nFor more details:\nhttps://docs.aws.amazon.com/sagemaker/latest/dg/nbi-root-access.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sagemaker-notebookinstance.html"
}


#
# PR-AWS-CLD-SGM-003
#

default sagemaker_direct_internet_access_enabled = true

sagemaker_direct_internet_access_enabled = false {
    # lower(resource.Type) == "aws::sagemaker::notebookinstance"
    lower(input.DirectInternetAccess) == "enabled"
}

sagemaker_direct_internet_access_enabled = false {
    # lower(resource.Type) == "aws::sagemaker::notebookinstance"
    not input.DirectInternetAccess
}

sagemaker_direct_internet_access_enabled_err = "AWS SageMaker notebook instance configured with direct internet access feature" {
    not sagemaker_direct_internet_access_enabled
}

sagemaker_direct_internet_access_enabled_metadata := {
    "Policy Code": "PR-AWS-CLD-SGM-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS SageMaker notebook instance configured with direct internet access feature",
    "Policy Description": "This policy identifies SageMaker notebook instances that are configured with direct internet access feature. If AWS SageMaker notebook instances are configured with direct internet access feature, any machine outside the VPC can establish a connection to these instances, which provides an additional avenue for unauthorized access to data and the opportunity for malicious activity.\n\nFor more details:\nhttps://docs.aws.amazon.com/sagemaker/latest/dg/appendix-notebook-and-internet-access.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sagemaker-notebookinstance.html"
}


#
# PR-AWS-CLD-SGM-004
#

default sagemaker_vpc = true

sagemaker_vpc = false {
    # lower(resource.Type) == "aws::sagemaker::notebookinstance"
    count(input.SubnetId) == 0
}

sagemaker_vpc = false {
    # lower(resource.Type) == "aws::sagemaker::notebookinstance"
    not input.SubnetId
}

sagemaker_vpc_err = "AWS SageMaker notebook instance is not placed in VPC" {
    not sagemaker_vpc
}

sagemaker_vpc_metadata := {
    "Policy Code": "PR-AWS-CLD-SGM-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS SageMaker notebook instance is not placed in VPC",
    "Policy Description": "This policy identifies SageMaker notebook instances that are not placed inside a VPC. It is recommended to place your SageMaker inside VPC so that VPC-only resources able to access your SageMaker data, which cannot be accessed outside a VPC network.\n\nFor more details:\nhttps://docs.aws.amazon.com/sagemaker/latest/dg/process-vpc.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sagemaker-notebookinstance.html"
}


#
# PR-AWS-CLD-SGM-005
# aws::sagemaker::notebookinstance
# AWS::KMS::Key

default sagemaker_customer_managed_key = true

sagemaker_customer_managed_key = false {
    X := input.TEST_SAGEMAKER[_]
    X.NotebookInstanceStatus == "InService"
    has_property(X, "KmsKeyId")
    Y := input.TEST_KMS[_]
    X.KmsKeyId == Y.KeyMetadata.KeyId
    Y.KeyMetadata.KeyManager == "AWS"
}

sagemaker_customer_managed_key_err = "Ensure AWS SageMaker notebook instance is encrypted using Customer Managed Key." {
    not sagemaker_customer_managed_key
}

sagemaker_customer_managed_key_metadata := {
    "Policy Code": "PR-AWS-CLD-SGM-005",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS SageMaker notebook instance is encrypted using Customer Managed Key.",
    "Policy Description": "It identifies SageMaker notebook instances that are not encrypted using Customer Managed Key. SageMaker notebook instances should be encrypted with Amazon KMS Customer Master Keys (CMKs) instead of AWS managed-keys in order to have more granular control over the data-at-rest encryption/decryption process and meet compliance requirements. For more details: https://docs.aws.amazon.com/sagemaker/latest/dg/encryption-at-rest.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sagemaker.html#SageMaker.Client.describe_notebook_instance"
}