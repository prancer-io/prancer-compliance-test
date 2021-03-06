package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-policy.html

#
# PR-AWS-0004-TRF
#

default s3_accesslog = null

aws_attribute_absence["s3_accesslog"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_s3_bucket"
    not resource.properties.logging.target_bucket
}

aws_attribute_absence["s3_accesslog"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_s3_bucket"
    not resource.properties.logging.target_prefix
}

aws_issue["s3_accesslog"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_s3_bucket"
    count(resource.properties.logging.target_bucket) == 0
}

aws_issue["s3_accesslog"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_s3_bucket"
    count(resource.properties.logging.target_prefix) == 0
}

s3_accesslog {
    lower(input.resources[_].type) == "aws_s3_bucket"
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

s3_accesslog_miss_err = "S3 Bucket attribute target_bucket/target_prefix missing in the resource" {
    aws_attribute_absence["s3_accesslog"]
}

s3_accesslog_metadata := {
    "Policy Code": "PR-AWS-0004-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Access logging not enabled on S3 buckets",
    "Policy Description": "Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets. It is recommended that Access logging is turned on for all S3 buckets to meet audit PR-AWS-0004-TRF-DESC compliance requirement",
    "Resource Type": "aws_s3_bucket_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-0140-TRF
#

default s3_acl_delete = null

aws_attribute_absence["s3_acl_delete"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    not resource.properties.policy.Statement
}

aws_issue["s3_acl_delete"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:*"
}

aws_issue["s3_acl_delete"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:delete"
}

s3_acl_delete {
    lower(input.resources[_].type) == "aws_s3_bucket_policy"
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

s3_acl_delete_miss_err = "S3 Policy attribute policy.Statement missing in the resource" {
    aws_attribute_absence["s3_acl_delete"]
}

s3_acl_delete_metadata := {
    "Policy Code": "PR-AWS-0140-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS S3 Bucket has Global DELETE Permissions enabled via bucket policy",
    "Policy Description": "This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to DELETE objects from a bucket. These permissions permit anyone, malicious or not, to DELETE objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.",
    "Resource Type": "aws_s3_bucket_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-0141-TRF
#

default s3_acl_get = null

aws_attribute_absence["s3_acl_get"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    not resource.properties.policy.Statement
}

aws_issue["s3_acl_get"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:*"
}

aws_issue["s3_acl_get"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:get"
}

s3_acl_get {
    lower(input.resources[_].type) == "aws_s3_bucket_policy"
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

s3_acl_get_miss_err = "S3 Policy attribute policy.Statement missing in the resource" {
    aws_attribute_absence["s3_acl_get"]
}

s3_acl_get_metadata := {
    "Policy Code": "PR-AWS-0141-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS S3 Bucket has Global GET Permissions enabled via bucket policy",
    "Policy Description": "This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to GET objects from a bucket. These permissions permit anyone, malicious or not, to GET objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.",
    "Resource Type": "aws_s3_bucket_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-0142-TRF
#

default s3_acl_list = null

aws_attribute_absence["s3_acl_list"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    not resource.properties.policy.Statement
}

aws_issue["s3_acl_list"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:*"
}

aws_issue["s3_acl_list"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:list"
}

s3_acl_list {
    lower(input.resources[_].type) == "aws_s3_bucket_policy"
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

s3_acl_list_miss_err = "S3 Policy attribute policy.Statement missing in the resource" {
    aws_attribute_absence["s3_acl_list"]
}

s3_acl_list_metadata := {
    "Policy Code": "PR-AWS-0142-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS S3 Bucket has Global LIST Permissions enabled via bucket policy",
    "Policy Description": "This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to LIST objects from a bucket. These permissions permit anyone, malicious or not, to LIST objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.",
    "Resource Type": "aws_s3_bucket_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-0143-TRF
#

default s3_acl_put = null

aws_attribute_absence["s3_acl_put"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    not resource.properties.policy.Statement
}

aws_issue["s3_acl_put"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:*"
}

aws_issue["s3_acl_put"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:put"
}

s3_acl_put {
    lower(input.resources[_].type) == "aws_s3_bucket_policy"
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

s3_acl_put_miss_err = "S3 Policy attribute policy.Statement missing in the resource" {
    aws_attribute_absence["s3_acl_put"]
}

s3_acl_put_metadata := {
    "Policy Code": "PR-AWS-0143-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS S3 Bucket has Global PUT Permissions enabled via bucket policy",
    "Policy Description": "This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to PUT objects into a bucket. These permissions permit anyone, malicious or not, to PUT objects into your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk compromise of critical data by leaving this open.",
    "Resource Type": "aws_s3_bucket_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-0145-TRF
#

default s3_versioning = null

aws_attribute_absence["s3_versioning"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_s3_bucket"
    not resource.properties.versioning.enabled
}

aws_issue["s3_versioning"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_s3_bucket"
    resource.properties.versioning.enabled != true
}

s3_versioning {
    lower(input.resources[_].type) == "aws_s3_bucket"
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

s3_versioning_miss_err = "S3 Bucket attribute versioning.enabled missing in the resource" {
    aws_attribute_absence["s3_versioning"]
}

s3_versioning_metadata := {
    "Policy Code": "PR-AWS-0145-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS S3 Object Versioning is disabled",
    "Policy Description": "This policy identifies the S3 buckets which have Object Versioning disabled. S3 Object Versioning is an important capability in protecting your data within a bucket. Once you enable Object Versioning, you cannot remove it; you can suspend Object Versioning at any time on a bucket if you do not wish for it to persist. It is recommended to enable Object Versioning on S3.",
    "Resource Type": "aws_s3_bucket_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-0148-TRF
#

default s3_transport = null

aws_attribute_absence["s3_transport"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    count([c | resource.properties.policy.Statement[_].Condition.StringLike["aws:SecureTransport"]; c := 1]) == 0
}

aws_issue["s3_transport"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    resource.properties.policy.Statement[_].Condition.StringLike["aws:SecureTransport"] != true
}

s3_transport {
    lower(input.resources[_].type) == "aws_s3_bucket_policy"
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
    "Policy Code": "PR-AWS-0148-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS S3 bucket not configured with secure data transport policy",
    "Policy Description": "This policy identifies S3 buckets which are not configured with secure data transport policy. AWS S3 buckets should enforce encryption of data over the network using Secure Sockets Layer (SSL). It is recommended to add a bucket policy that explicitly denies (Effect: Deny) all access (Action: s3:*) from anybody who browses (Principal: *) to Amazon S3 objects within an Amazon S3 bucket if they are not accessed through HTTPS (aws:SecureTransport: false).",
    "Resource Type": "aws_s3_bucket_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}

#
# PR-AWS-0362-TRF
#

default s3_website = null

aws_issue["s3_website"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_s3_bucket"
    resource.properties.website
}

s3_website {
    lower(input.resources[_].type) == "aws_s3_bucket"
    not aws_issue["s3_website"]
}

s3_website = false {
    aws_issue["s3_website"]
}

s3_website_err = "S3 buckets with configurations set to host websites" {
    aws_issue["s3_website"]
}

s3_website_metadata := {
    "Policy Code": "PR-AWS-0362-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "",
    "Policy Description": "",
    "Resource Type": "aws_s3_bucket_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html"
}
