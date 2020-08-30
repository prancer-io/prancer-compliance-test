package rule

sqs {
    resource := input.Resources[_]
    resource.Type="AWS::SQS::Queue"
    resource.Properties.MessageRetentionPeriod
    resource.Properties.MessageRetentionPeriod != null
    resource.Properties.MessageRetentionPeriod != ""
}

sqs = false {
    resource := input.Resources[_]
    resource.Type="AWS::SQS::Queue"
    not resource.Properties.MessageRetentionPeriod
}

sqs_err = "AWS SQS message retention period is not set" {
    sqs == false
}
