package rule

default rulepass = true

# API: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html
# Id: 130

rulepass = false {
        input.DBInstances[_].AutoMinorVersionUpgrade = false
}
