package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-queues.html

#
# Id: 155
#

default sqs_deadletter = null

sqs_deadletter {
    lower(input.Type) == "aws::sqs::queue"
    input.Properties.RedrivePolicy.deadLetterTargetArn
}

sqs_deadletter = false {
    lower(input.Type) == "aws::sqs::queue"
    not input.Properties.RedrivePolicy
}

sqs_deadletter = false {
    lower(input.Type) == "aws::sqs::queue"
    not input.Properties.RedrivePolicy.deadLetterTargetArn
}

sqs_deadletter_err = "AWS SQS does not have a dead letter queue configured" {
    sqs_deadletter == false
}

#
# Id: 156
#

default sqs_encrypt_key = null

sqs_encrypt_key {
    lower(input.Type) == "aws::sqs::queue"
    not contains(lower(input.Properties.KmsMasterKeyId), "alias/aws/sqs")
}

sqs_encrypt_key {
    lower(input.Type) == "aws::sqs::queue"
    not input.Properties.KmsMasterKeyId
}

sqs_encrypt_key = false {
    lower(input.Type) == "aws::sqs::queue"
    contains(lower(input.Properties.KmsMasterKeyId), "alias/aws/sqs")
}

sqs_encrypt_key_err = "AWS SQS queue encryption using default KMS key instead of CMK" {
    sqs_encrypt_key == false
}

#
# Id: 156
#

default sqs_encrypt = null

sqs_encrypt {
    lower(input.Type) == "aws::sqs::queue"
    count(input.Properties.KmsMasterKeyId) > 0
}

sqs_encrypt = false {
    lower(input.Type) == "aws::sqs::queue"
    not input.Properties.KmsMasterKeyId
}

sqs_encrypt = false {
    lower(input.Type) == "aws::sqs::queue"
    count(input.Properties.KmsMasterKeyId) == 0
}

sqs_encrypt_err = "AWS SQS server side encryption not enabled" {
    sqs_encrypt == false
}
