package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html
# Id: 122

rulepass {
    instance := input.DBInstances[_]
    instance.PerformanceInsightsKMSKeyId
}
