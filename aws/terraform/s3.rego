package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-policy.html

#
# PR-AWS-0004-TRF
#

default s3_accesslog = null

aws_attribute_absence["s3_accesslog"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_s3_bucket"
    not resource.properties.logging.target_bucket
}

aws_attribute_absence["s3_accesslog"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_s3_bucket"
    not resource.properties.logging.target_prefix
}

aws_issue["s3_accesslog"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_s3_bucket"
    count(resource.properties.logging.target_bucket) == 0
}

aws_issue["s3_accesslog"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_s3_bucket"
    count(resource.properties.logging.target_prefix) == 0
}

s3_accesslog {
    lower(input.json.resources[_].type) == "aws_s3_bucket"
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

#
# PR-AWS-0140-TRF
#

default s3_acl_delete = null

aws_attribute_absence["s3_acl_delete"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    not resource.properties.policy.Statement
}

aws_issue["s3_acl_delete"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:*"
}

aws_issue["s3_acl_delete"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:delete"
}

s3_acl_delete {
    lower(input.json.resources[_].type) == "aws_s3_bucket_policy"
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

#
# PR-AWS-0141-TRF
#

default s3_acl_get = null

aws_attribute_absence["s3_acl_get"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    not resource.properties.policy.Statement
}

aws_issue["s3_acl_get"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:*"
}

aws_issue["s3_acl_get"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:get"
}

s3_acl_get {
    lower(input.json.resources[_].type) == "aws_s3_bucket_policy"
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

#
# PR-AWS-0142-TRF
#

default s3_acl_list = null

aws_attribute_absence["s3_acl_list"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    not resource.properties.policy.Statement
}

aws_issue["s3_acl_list"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:*"
}

aws_issue["s3_acl_list"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:list"
}

s3_acl_list {
    lower(input.json.resources[_].type) == "aws_s3_bucket_policy"
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

#
# PR-AWS-0143-TRF
#

default s3_acl_put = null

aws_attribute_absence["s3_acl_put"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    not resource.properties.policy.Statement
}

aws_issue["s3_acl_put"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:*"
}

aws_issue["s3_acl_put"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    stat := resource.properties.policy.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:put"
}

s3_acl_put {
    lower(input.json.resources[_].type) == "aws_s3_bucket_policy"
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

#
# PR-AWS-0145-TRF
#

default s3_versioning = null

aws_attribute_absence["s3_versioning"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_s3_bucket"
    not resource.properties.versioning.enabled
}

aws_issue["s3_versioning"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_s3_bucket"
    resource.properties.versioning.enabled != true
}

s3_versioning {
    lower(input.json.resources[_].type) == "aws_s3_bucket"
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

#
# PR-AWS-0148-TRF
#

default s3_transport = null

aws_attribute_absence["s3_transport"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    count([c | resource.properties.policy.Statement[_].Condition.StringLike["aws:SecureTransport"]; c := 1]) == 0
}

aws_issue["s3_transport"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_s3_bucket_policy"
    resource.properties.policy.Statement[_].Condition.StringLike["aws:SecureTransport"] != true
}

s3_transport {
    lower(input.json.resources[_].type) == "aws_s3_bucket_policy"
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
# PR-AWS-0362-TRF
#

default s3_website = null

aws_issue["s3_website"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_s3_bucket"
    resource.properties.website
}

s3_website {
    lower(input.json.resources[_].type) == "aws_s3_bucket"
    not aws_issue["s3_website"]
}

s3_website = false {
    aws_issue["s3_website"]
}

s3_website_err = "S3 buckets with configurations set to host websites" {
    aws_issue["s3_website"]
}
