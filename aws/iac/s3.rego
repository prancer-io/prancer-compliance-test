package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-policy.html

#
# PR-AWS-0004-CFR
#

default s3_accesslog = null

aws_attribute_absence["s3_accesslog"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.LoggingConfiguration.DestinationBucketName
}

aws_attribute_absence["s3_accesslog"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.LoggingConfiguration.LogFilePrefix
}

aws_issue["s3_accesslog"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::s3::bucket"
    count(resource.Properties.LoggingConfiguration.DestinationBucketName) == 0
}

aws_issue["s3_accesslog"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::s3::bucket"
    count(resource.Properties.LoggingConfiguration.LogFilePrefix) == 0
}

s3_accesslog {
    lower(input.resources[_].Type) == "aws::s3::bucket"
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

#
# PR-AWS-0140-CFR
#

default s3_acl_delete = null

aws_attribute_absence["s3_acl_delete"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    not resource.Properties.PolicyDocument.Statement
}

aws_issue["s3_acl_delete"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:*"
}

aws_issue["s3_acl_delete"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:delete"
}

s3_acl_delete {
    lower(input.resources[_].Type) == "aws::s3::bucketpolicy"
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

#
# PR-AWS-0141-CFR
#

default s3_acl_get = null

aws_attribute_absence["s3_acl_get"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    not resource.Properties.PolicyDocument.Statement
}

aws_issue["s3_acl_get"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:*"
}

aws_issue["s3_acl_get"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:get"
}

s3_acl_get {
    lower(input.resources[_].Type) == "aws::s3::bucketpolicy"
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

#
# PR-AWS-0142-CFR
#

default s3_acl_list = null

aws_attribute_absence["s3_acl_list"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    not resource.Properties.PolicyDocument.Statement
}

aws_issue["s3_acl_list"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:*"
}

aws_issue["s3_acl_list"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:list"
}

s3_acl_list {
    lower(input.resources[_].Type) == "aws::s3::bucketpolicy"
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

#
# PR-AWS-0143-CFR
#

default s3_acl_put = null

aws_attribute_absence["s3_acl_put"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    not resource.Properties.PolicyDocument.Statement
}

aws_issue["s3_acl_put"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:*"
}

aws_issue["s3_acl_put"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    stat := resource.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:put"
}

s3_acl_put {
    lower(input.resources[_].Type) == "aws::s3::bucketpolicy"
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

#
# PR-AWS-0145-CFR
#

default s3_versioning = null

aws_attribute_absence["s3_versioning"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.VersioningConfiguration.Status
}

aws_issue["s3_versioning"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::s3::bucket"
    lower(resource.Properties.VersioningConfiguration.Status) != "enabled"
}

s3_versioning {
    lower(input.resources[_].Type) == "aws::s3::bucket"
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

#
# PR-AWS-0148-CFR
#

default s3_transport = null

aws_attribute_absence["s3_transport"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    count([c | resource.Properties.PolicyDocument.Statement[_].Condition.StringLike["aws:SecureTransport"]; c := 1]) == 0
}

aws_issue["s3_transport"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::s3::bucketpolicy"
    resource.Properties.PolicyDocument.Statement[_].Condition.StringLike["aws:SecureTransport"] != true
}

s3_transport {
    lower(input.resources[_].Type) == "aws::s3::bucketpolicy"
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

#
# PR-AWS-0196-CFR
#

default s3_website = null

aws_issue["s3_website"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::s3::bucket"
    resource.Properties.WebsiteConfiguration
}

s3_website {
    lower(input.resources[_].Type) == "aws::s3::bucket"
    not aws_issue["s3_website"]
}

s3_website = false {
    aws_issue["s3_website"]
}

s3_website_err = "S3 buckets with configurations set to host websites" {
    aws_issue["s3_website"]
}
