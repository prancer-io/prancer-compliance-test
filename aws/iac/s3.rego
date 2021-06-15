package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-policy.html

#
# PR-AWS-0004-CFR
#

default s3_accesslog = null

aws_attribute_absence["s3_accesslog"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.LoggingConfiguration.DestinationBucketName
}

aws_attribute_absence["s3_accesslog"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.LoggingConfiguration.LogFilePrefix
}

aws_issue["s3_accesslog"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    count(resource.Properties.LoggingConfiguration.DestinationBucketName) == 0
}

aws_issue["s3_accesslog"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    count(resource.Properties.LoggingConfiguration.LogFilePrefix) == 0
}

s3_accesslog {
    lower(input.Resources[i].Type) == "aws::s3::bucket"
    not aws_issue["s3_accesslog"]
    not aws_attribute_absence["s3_accesslog"]
}

s3_accesslog = false {
    aws_issue["s3_accesslog"]
}

s3_accesslog = false {
    aws_attribute_absence["s3_accesslog"]
}

s3_accesslog_err = "AWS Access logging not enabled on S3 buckets" {
    aws_issue["s3_accesslog"]
}

s3_accesslog_miss_err = "S3 Bucket attribute DestinationBucketName/LogFilePrefix missing in the resource" {
    aws_attribute_absence["s3_accesslog"]
}

s3_accesslog_metadata := {
    "Policy Code": "PR-AWS-0004-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Access logging not enabled on S3 buckets",
    "Policy Description": "Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets. It is recommended that Access logging is turned on for all S3 buckets to meet audit PR-AWS-0004-CFR-DESC compliance requirement",
    "Compliance": ["CSA-CCM","GDPR","HITRUST","NIST 800","PCI-DSS","SOC 2"],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-0140-CFR
#

default s3_acl_delete = null

aws_attribute_absence["s3_acl_delete"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    not resource.Properties.PolicyDocument.Statement
}

aws_issue["s3_acl_delete"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:*"
}

aws_issue["s3_acl_delete"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:delete"
}

s3_acl_delete {
    lower(input.Resources[i].Type) == "aws::s3::bucketpolicy"
    not aws_issue["s3_acl_delete"]
    not aws_attribute_absence["s3_acl_delete"]
}

s3_acl_delete = false {
    aws_issue["s3_acl_delete"]
}

s3_acl_delete = false {
    aws_attribute_absence["s3_acl_delete"]
}

s3_acl_delete_err = "AWS S3 Bucket has Global DELETE Permissions enabled via bucket policy" {
    aws_issue["s3_acl_delete"]
}

s3_acl_delete_miss_err = "S3 Policy attribute PolicyDocument.Statement missing in the resource" {
    aws_attribute_absence["s3_acl_delete"]
}

s3_acl_delete_metadata := {
    "Policy Code": "PR-AWS-0140-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS S3 Bucket has Global DELETE Permissions enabled via bucket policy",
    "Policy Description": "This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to DELETE objects from a bucket. These permissions permit anyone, malicious or not, to DELETE objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.",
    "Compliance": [],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-0141-CFR
#

default s3_acl_get = null

aws_attribute_absence["s3_acl_get"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    not resource.Properties.PolicyDocument.Statement
}

aws_issue["s3_acl_get"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:*"
}

aws_issue["s3_acl_get"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:get"
}

s3_acl_get {
    lower(input.Resources[i].Type) == "aws::s3::bucketpolicy"
    not aws_issue["s3_acl_get"]
    not aws_attribute_absence["s3_acl_get"]
}

s3_acl_get = false {
    aws_issue["s3_acl_get"]
}

s3_acl_get = false {
    aws_attribute_absence["s3_acl_get"]
}

s3_acl_get_err = "AWS S3 Bucket has Global get Permissions enabled via bucket policy" {
    aws_issue["s3_acl_get"]
}

s3_acl_get_miss_err = "S3 Policy attribute PolicyDocument.Statement missing in the resource" {
    aws_attribute_absence["s3_acl_get"]
}

s3_acl_get_metadata := {
    "Policy Code": "PR-AWS-0141-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS S3 Bucket has Global GET Permissions enabled via bucket policy",
    "Policy Description": "This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to GET objects from a bucket. These permissions permit anyone, malicious or not, to GET objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.",
    "Compliance": [],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-0142-CFR
#

default s3_acl_list = null

aws_attribute_absence["s3_acl_list"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    not resource.Properties.PolicyDocument.Statement
}

aws_issue["s3_acl_list"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:*"
}

aws_issue["s3_acl_list"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:list"
}

s3_acl_list {
    lower(input.Resources[i].Type) == "aws::s3::bucketpolicy"
    not aws_issue["s3_acl_list"]
    not aws_attribute_absence["s3_acl_list"]
}

s3_acl_list = false {
    aws_issue["s3_acl_list"]
}

s3_acl_list = false {
    aws_attribute_absence["s3_acl_list"]
}

s3_acl_list_err = "AWS S3 Bucket has Global list Permissions enabled via bucket policy" {
    aws_issue["s3_acl_list"]
}

s3_acl_list_miss_err = "S3 Policy attribute PolicyDocument.Statement missing in the resource" {
    aws_attribute_absence["s3_acl_list"]
}

s3_acl_list_metadata := {
    "Policy Code": "PR-AWS-0142-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS S3 Bucket has Global LIST Permissions enabled via bucket policy",
    "Policy Description": "This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to LIST objects from a bucket. These permissions permit anyone, malicious or not, to LIST objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.",
    "Compliance": [],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-0143-CFR
#

default s3_acl_put = null

aws_attribute_absence["s3_acl_put"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    not resource.Properties.PolicyDocument.Statement
}

aws_issue["s3_acl_put"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:*"
}

aws_issue["s3_acl_put"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:put"
}

s3_acl_put {
    lower(input.Resources[i].Type) == "aws::s3::bucketpolicy"
    not aws_issue["s3_acl_put"]
    not aws_attribute_absence["s3_acl_put"]
}

s3_acl_put = false {
    aws_issue["s3_acl_put"]
}

s3_acl_put = false {
    aws_attribute_absence["s3_acl_put"]
}

s3_acl_put_err = "AWS S3 Bucket has Global put Permissions enabled via bucket policy" {
    aws_issue["s3_acl_put"]
}

s3_acl_put_miss_err = "S3 Policy attribute PolicyDocument.Statement missing in the resource" {
    aws_attribute_absence["s3_acl_put"]
}

s3_acl_put_metadata := {
    "Policy Code": "PR-AWS-0143-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS S3 Bucket has Global PUT Permissions enabled via bucket policy",
    "Policy Description": "This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to PUT objects into a bucket. These permissions permit anyone, malicious or not, to PUT objects into your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk compromise of critical data by leaving this open.",
    "Compliance": [],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-0145-CFR
#

default s3_versioning = null

aws_attribute_absence["s3_versioning"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.VersioningConfiguration.Status
}

aws_issue["s3_versioning"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    lower(resource.Properties.VersioningConfiguration.Status) != "enabled"
}

s3_versioning {
    lower(input.Resources[i].Type) == "aws::s3::bucket"
    not aws_issue["s3_versioning"]
    not aws_attribute_absence["s3_versioning"]
}

s3_versioning = false {
    aws_issue["s3_versioning"]
}

s3_versioning = false {
    aws_attribute_absence["s3_versioning"]
}

s3_versioning_err = "AWS S3 Object Versioning is disabled" {
    aws_issue["s3_versioning"]
}

s3_versioning_miss_err = "S3 Bucket attribute VersioningConfiguration.Status missing in the resource" {
    aws_attribute_absence["s3_versioning"]
}

s3_versioning_metadata := {
    "Policy Code": "PR-AWS-0145-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS S3 Object Versioning is disabled",
    "Policy Description": "This policy identifies the S3 buckets which have Object Versioning disabled. S3 Object Versioning is an important capability in protecting your data within a bucket. Once you enable Object Versioning, you cannot remove it; you can suspend Object Versioning at any time on a bucket if you do not wish for it to persist. It is recommended to enable Object Versioning on S3.",
    "Compliance": [],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-0148-CFR
#

default s3_transport = null

aws_attribute_absence["s3_transport"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    count([c | resource.Properties.PolicyDocument.Statement[_].Condition.StringLike["aws:SecureTransport"]; c := 1]) == 0
}

aws_issue["s3_transport"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    resource.Properties.PolicyDocument.Statement[_].Condition.StringLike["aws:SecureTransport"] != true
}

s3_transport {
    lower(input.Resources[i].Type) == "aws::s3::bucketpolicy"
    not aws_issue["s3_transport"]
    not aws_attribute_absence["s3_transport"]
}

s3_transport = false {
    aws_issue["s3_transport"]
}

s3_transport = false {
    aws_attribute_absence["s3_transport"]
}

s3_transport_err = "AWS S3 bucket not configured with secure data transport policy" {
    aws_issue["s3_transport"]
}

s3_transport_miss_err = "S3 Policy attribute Condition SecureTransport missing in the resource" {
    aws_attribute_absence["s3_transport"]
}

s3_transport_metadata := {
    "Policy Code": "PR-AWS-0148-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS S3 bucket not configured with secure data transport policy",
    "Policy Description": "This policy identifies S3 buckets which are not configured with secure data transport policy. AWS S3 buckets should enforce encryption of data over the network using Secure Sockets Layer (SSL). It is recommended to add a bucket policy that explicitly denies (Effect: Deny) all access (Action: s3:*) from anybody who browses (Principal: *) to Amazon S3 objects within an Amazon S3 bucket if they are not accessed through HTTPS (aws:SecureTransport: false).",
    "Compliance": [],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-0196-CFR
#

default s3_website = null

aws_issue["s3_website"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    resource.Properties.WebsiteConfiguration
}

s3_website {
    lower(input.Resources[i].Type) == "aws::s3::bucket"
    not aws_issue["s3_website"]
}

s3_website = false {
    aws_issue["s3_website"]
}

s3_website_err = "S3 buckets with configurations set to host websites" {
    aws_issue["s3_website"]
}

s3_website_metadata := {
    "Policy Code": "PR-AWS-0196-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "S3 buckets with configurations set to host websites",
    "Policy Description": "To host a website on AWS S3 you should configure a bucket as a website. This policy identifies all the S3 buckets that are configured to host websites. By frequently surveying these S3 buckets you can ensure that only authorized buckets are enabled to host websites. Make sure to disable static website hosting for unauthorized S3 buckets.",
    "Compliance": ["ISO 27001"],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}
