#
# PR-AWS-0130
#

package rule

default rulepass = true

# API: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html

rulepass = false {
    # lower(input.json.Type) == "aws::rds::dbinstance"
    input.json.DBInstances[_].AutoMinorVersionUpgrade = false
}

metadata := {
    "Policy Code": "PR-AWS-0130",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS RDS minor upgrades not enabled",
    "Policy Description": "When Amazon Relational Database Service (Amazon RDS) supports a new version of a database engine, you can upgrade your DB instances to the new version. There are two kinds of upgrades: major version upgrades and minor version upgrades. Minor upgrades helps maintain a secure and stable RDS with minimal impact on the application. For this reason, we recommend that your automatic minor upgrade is enabled. Minor version upgrades only occur automatically if a minor upgrade replaces an unsafe version, such as a minor upgrade that contains bug fixes for a previous version.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html"
}
