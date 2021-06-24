#
# PR-AWS-0122
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html

rulepass {
    # lower(input.json.Type) == "aws::rds::dbinstance"
    instance := input.json.DBInstances[_]
    instance.PerformanceInsightsKMSKeyId
}

metadata := {
    "Policy Code": "PR-AWS-0122",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS RDS database not encrypted using Customer Managed Key",
    "Policy Description": "This policy identifies RDS databases that are encrypted with default KMS keys and not with customer managed keys. As a best practice, use customer managed keys to encrypt the data on your RDS databases and maintain control of your keys and data on sensitive workloads.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html"
}
