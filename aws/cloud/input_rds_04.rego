package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html
# Id: 121

rulepass = true{
   db_instance := input.DBInstances[_]
   db_instance.PubliclyAccessible == false
}

# If database instance publicly accessible is disabled then test will pass.