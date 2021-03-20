#
# PR-AWS-0119
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBClusters.html
# Id: 119

rulepass {
    lower(resource.Type) == "aws::rds::dbcluster"
   db_cluster := input.DBClusters[_]
   db_cluster.StorageEncrypted == true
}
