package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-policy.html

#
# Id: 4
#

default s3_accesslog = null

s3_accesslog {
    lower(input.Type) == "aws::s3::bucket"
    count(input.Properties.LoggingConfiguration.DestinationBucketName) > 0
    count(input.Properties.LoggingConfiguration.LogFilePrefix) > 0
}

s3_accesslog = false {
    lower(input.Type) == "aws::s3::bucket"
    count(input.Properties.LoggingConfiguration.DestinationBucketName) == 0
}

s3_accesslog = false {
    lower(input.Type) == "aws::s3::bucket"
    not input.Properties.LoggingConfiguration
}

s3_accesslog = false {
    lower(input.Type) == "aws::s3::bucket"
    not input.Properties.LoggingConfiguration.DestinationBucketName
}

s3_accesslog = false {
    lower(input.Type) == "aws::s3::bucket"
    count(input.Properties.LoggingConfiguration.DestinationBucketName) == 0
}

s3_accesslog = false {
    lower(input.Type) == "aws::s3::bucket"
    not input.Properties.LoggingConfiguration.LogFilePrefix
}

s3_accesslog = false {
    lower(input.Type) == "aws::s3::bucket"
    count(input.Properties.LoggingConfiguration.LogFilePrefix) == 0
}

s3_accesslog_err = "AWS Access logging not enabled on S3 buckets" {
    s3_accesslog == false
}

#
# Id: 140
#

default s3_acl_delete = null

s3_acl_delete {
    lower(input.Type) == "aws::s3::bucketpolicy"
    stat := input.Properties.PolicyDocument.Statement[_]
    count([c | lower(stat.Effect) == "allow"; c := 1]) == 0
}

s3_acl_delete {
    lower(input.Type) == "aws::s3::bucketpolicy"
    stat := input.Properties.PolicyDocument.Statement[_]
    count([c | lower(stat.Principal) == "*"; c := 1]) == 0
}

s3_acl_delete {
    lower(input.Type) == "aws::s3::bucketpolicy"
    count([c | lower(input.Properties.PolicyDocument.Statement[_].Action[_]) == "s3:*"; c := 1]) == 0
    count([c | lower(input.Properties.PolicyDocument.Statement[_].Action[_]) == "s3:delete"; c := 1]) == 0
}

s3_acl_delete {
    lower(input.Type) == "aws::s3::bucketpolicy"
    count([c | stat := input.Properties.PolicyDocument.Statement[_]; lower(stat.Effect) == "allow"; stat.Principal == "*"; lower(stat.Action[_]) == "s3:*"; c := 1]) == 0
    count([c | stat := input.Properties.PolicyDocument.Statement[_]; lower(stat.Effect) == "allow"; stat.Principal == "*"; lower(stat.Action[_]) == "s3:delete"; c := 1]) == 0
}

s3_acl_delete = false {
    lower(input.Type) == "aws::s3::bucketpolicy"
    stat := input.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:*"
}

s3_acl_delete = false {
    lower(input.Type) == "aws::s3::bucketpolicy"
    stat := input.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:delete"
}

s3_acl_delete_err = "AWS S3 Bucket has Global DELETE Permissions enabled via bucket policy" {
    s3_acl_delete == false
}

#
# Id: 141
#

default s3_acl_get = null

s3_acl_get {
    lower(input.Type) == "aws::s3::bucketpolicy"
    stat := input.Properties.PolicyDocument.Statement[_]
    count([c | lower(stat.Effect) == "allow"; c := 1]) == 0
}

s3_acl_get {
    lower(input.Type) == "aws::s3::bucketpolicy"
    stat := input.Properties.PolicyDocument.Statement[_]
    count([c | lower(stat.Principal) == "*"; c := 1]) == 0
}

s3_acl_get {
    lower(input.Type) == "aws::s3::bucketpolicy"
    count([c | lower(input.Properties.PolicyDocument.Statement[_].Action[_]) == "s3:*"; c := 1]) == 0
    count([c | lower(input.Properties.PolicyDocument.Statement[_].Action[_]) == "s3:get"; c := 1]) == 0
}

s3_acl_get {
    lower(input.Type) == "aws::s3::bucketpolicy"
    count([c | stat := input.Properties.PolicyDocument.Statement[_]; lower(stat.Effect) == "allow"; stat.Principal == "*"; lower(stat.Action[_]) == "s3:*"; c := 1]) == 0
    count([c | stat := input.Properties.PolicyDocument.Statement[_]; lower(stat.Effect) == "allow"; stat.Principal == "*"; lower(stat.Action[_]) == "s3:get"; c := 1]) == 0
}

s3_acl_get = false {
    lower(input.Type) == "aws::s3::bucketpolicy"
    stat := input.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:*"
}

s3_acl_get = false {
    lower(input.Type) == "aws::s3::bucketpolicy"
    stat := input.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:get"
}

s3_acl_get_err = "AWS S3 Bucket has Global GET Permissions enabled via bucket policy" {
    s3_acl_get == false
}

#
# Id: 142
#

default s3_acl_list = null

s3_acl_list {
    lower(input.Type) == "aws::s3::bucketpolicy"
    stat := input.Properties.PolicyDocument.Statement[_]
    count([c | lower(stat.Effect) == "allow"; c := 1]) == 0
}

s3_acl_list {
    lower(input.Type) == "aws::s3::bucketpolicy"
    stat := input.Properties.PolicyDocument.Statement[_]
    count([c | lower(stat.Principal) == "*"; c := 1]) == 0
}

s3_acl_list {
    lower(input.Type) == "aws::s3::bucketpolicy"
    count([c | lower(input.Properties.PolicyDocument.Statement[_].Action[_]) == "s3:*"; c := 1]) == 0
    count([c | lower(input.Properties.PolicyDocument.Statement[_].Action[_]) == "s3:list"; c := 1]) == 0
}

s3_acl_list {
    lower(input.Type) == "aws::s3::bucketpolicy"
    count([c | stat := input.Properties.PolicyDocument.Statement[_]; lower(stat.Effect) == "allow"; stat.Principal == "*"; lower(stat.Action[_]) == "s3:*"; c := 1]) == 0
    count([c | stat := input.Properties.PolicyDocument.Statement[_]; lower(stat.Effect) == "allow"; stat.Principal == "*"; lower(stat.Action[_]) == "s3:list"; c := 1]) == 0
}

s3_acl_list = false {
    lower(input.Type) == "aws::s3::bucketpolicy"
    stat := input.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:*"
}

s3_acl_list = false {
    lower(input.Type) == "aws::s3::bucketpolicy"
    stat := input.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:list"
}

s3_acl_list_err = "AWS S3 Bucket has Global LIST Permissions enabled via bucket policy" {
    s3_acl_list == false
}

#
# Id: 143
#

default s3_acl_put = null

s3_acl_put {
    lower(input.Type) == "aws::s3::bucketpolicy"
    stat := input.Properties.PolicyDocument.Statement[_]
    count([c | lower(stat.Effect) == "allow"; c := 1]) == 0
}

s3_acl_put {
    lower(input.Type) == "aws::s3::bucketpolicy"
    stat := input.Properties.PolicyDocument.Statement[_]
    count([c | lower(stat.Principal) == "*"; c := 1]) == 0
}

s3_acl_put {
    lower(input.Type) == "aws::s3::bucketpolicy"
    count([c | lower(input.Properties.PolicyDocument.Statement[_].Action[_]) == "s3:*"; c := 1]) == 0
    count([c | lower(input.Properties.PolicyDocument.Statement[_].Action[_]) == "s3:put"; c := 1]) == 0
}

s3_acl_put {
    lower(input.Type) == "aws::s3::bucketpolicy"
    count([c | stat := input.Properties.PolicyDocument.Statement[_]; lower(stat.Effect) == "allow"; stat.Principal == "*"; lower(stat.Action[_]) == "s3:*"; c := 1]) == 0
    count([c | stat := input.Properties.PolicyDocument.Statement[_]; lower(stat.Effect) == "allow"; stat.Principal == "*"; lower(stat.Action[_]) == "s3:put"; c := 1]) == 0
}

s3_acl_put = false {
    lower(input.Type) == "aws::s3::bucketpolicy"
    stat := input.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:*"
}

s3_acl_put = false {
    lower(input.Type) == "aws::s3::bucketpolicy"
    stat := input.Properties.PolicyDocument.Statement[_]
    lower(stat.Effect) == "allow"
    stat.Principal == "*"
    lower(stat.Action[_]) == "s3:put"
}

s3_acl_put_err = "AWS S3 Bucket has Global PUT Permissions enabled via bucket policy" {
    s3_acl_put == false
}

#
# Id: 145
#

default s3_versioning = null

s3_versioning {
    lower(input.Type) == "aws::s3::bucket"
    lower(input.Properties.VersioningConfiguration.Status) == "enabled"
}

s3_versioning = false {
    lower(input.Type) == "aws::s3::bucket"
    lower(input.Properties.VersioningConfiguration.Status) != "enabled"
}

s3_versioning = false {
    lower(input.Type) == "aws::s3::bucket"
    not input.Properties.VersioningConfiguration
}

s3_versioning_err = "AWS S3 Object Versioning is disabled" {
    s3_versioning == false
}

#
# Id: 148
#

default s3_transport = null

s3_transport {
    lower(input.Type) == "aws::s3::bucketpolicy"
    count([c | input.Properties.PolicyDocument.Statement[_].Condition.StringLike["aws:SecureTransport"] == true; c := 1]) == count(input.Properties.PolicyDocument.Statement) 
}

s3_transport = false {
    lower(input.Type) == "aws::s3::bucketpolicy"
    stat := input.Properties.PolicyDocument.Statement[_]
    not stat.Condition.StringLike["aws:SecureTransport"]
}

s3_transport = false {
    lower(input.Type) == "aws::s3::bucketpolicy"
    input.Properties.PolicyDocument.Statement[_].Condition.StringLike["aws:SecureTransport"] == false
}

s3_transport_err = "AWS S3 bucket not configured with secure data transport policy" {
    s3_transport == false
}

#
# Id: 362
#

default s3_website = null

s3_website {
    lower(input.Type) == "aws::s3::bucket"
    not input.Properties.WebsiteConfiguration
}

s3_website = false {
    lower(input.Type) == "aws::s3::bucket"
    input.Properties.WebsiteConfiguration
}

s3_website_err = "S3 buckets with configurations set to host websites" {
    s3_website == false
}
