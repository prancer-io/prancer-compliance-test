#
# PR-AWS-0121
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html

rulepass {
    # lower(input.json.Type) == "aws::rds::dbinstance"
    db_instance := input.json.DBInstances[_]
    db_instance.PubliclyAccessible == false
}

metadata := {
    "Policy Code": "PR-AWS-0121",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS RDS database instance is publicly accessible",
    "Policy Description": "This policy identifies RDS database instances which are publicly accessible.DB instances should not be publicly accessible to protect the integrety of data.Public accessibility of DB instances can be modified by turning on or off the Public accessibility parameter.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html"
}

# If database instance publicly accessible is disabled then test will pass.
