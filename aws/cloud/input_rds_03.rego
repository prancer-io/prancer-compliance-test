package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html
# Id: 128

rulepass = true{
   db_instance := input.DBInstances[_]
   db_instance.CopyTagsToSnapshot == true
}

# If CopyTagsToSnapshot is enabled then test will pass.