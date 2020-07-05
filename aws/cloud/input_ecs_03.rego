package rule

default rulepass = false

# API Documentation: https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DescribeTaskDefinition.html
# Id: 48

rulepass {
    startswith(input.taskDefinition.executionRoleArn, "arn:aws:iam")
}
