package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sns-topic.html

#
# Id: 152
#

default sns_protocol = null

sns_protocol {
    lower(input.Type) == "aws::sns::subscription"
    lower(input.Properties.Protocol) != "http"
}

sns_protocol = false {
    lower(input.Type) == "aws::sns::subscription"
    lower(input.Properties.Protocol) == "http"
}

sns_protocol_err = "AWS SNS subscription is not configured with HTTPS" {
    sns_protocol == false
}

#
# Id: 153
#

default sns_encrypt_key = null

sns_encrypt_key {
    lower(input.Type) == "aws::sns::topic"
    not contains(lower(input.Properties.KmsMasterKeyId), "alias/aws/sns")
}

sns_encrypt_key {
    lower(input.Type) == "aws::sns::topic"
    not input.Properties.KmsMasterKeyId
}

sns_encrypt_key = false {
    lower(input.Type) == "aws::sns::topic"
    contains(lower(input.Properties.KmsMasterKeyId), "alias/aws/sns")
}

sns_encrypt_key_err = "AWS SNS topic encrypted using default KMS key instead of CMK" {
    sns_encrypt_key == false
}

#
# Id: 154
#

default sns_encrypt = null

sns_encrypt {
    lower(input.Type) == "aws::sns::topic"
    count(input.Properties.KmsMasterKeyId) > 0
}

sns_encrypt = false {
    lower(input.Type) == "aws::sns::topic"
    not input.Properties.KmsMasterKeyId
}

sns_encrypt = false {
    lower(input.Type) == "aws::sns::topic"
    count(input.Properties.KmsMasterKeyId) == 0
}

sns_encrypt_err = "AWS SNS topic with server-side encryption disabled" {
    sns_encrypt == false
}
