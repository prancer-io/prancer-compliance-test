



# Prancer Compliance test

## Introduction

### Prancer is a pre-deployment and post-deployment multi-cloud security platform for your Infrastructure as Code (IaC) and live cloud environment. It shifts the security to the left and provides end-to-end security scanning based on the Policy as Code concept. DevOps engineers can use it for static code analysis on IaC to find security drifts and maintain their cloud security posture with continuous compliance features.


----------------------------------------------------


#### These are list of policies related to AWS Controllers for Kubernetes. ACK is a new tool that lets you directly manage AWS services from Kubernetes.


----------------------------------------------------


***<font color="white">Master Test ID:</font>*** TEST_API_GATEWAY

***<font color="white">ID:</font>*** PR-AWS-0002-ACK

***Title: [AWS API Gateway endpoints without client certificate authentication]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_DYNAMODB

***<font color="white">ID:</font>*** PR-AWS-0036-ACK

***Title: [AWS DynamoDB encrypted using AWS owned CMK instead of AWS managed CMK]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_ELASTIC_CACHE_1

***<font color="white">ID:</font>*** PR-AWS-0055-ACK

***Title: [AWS ElastiCache Redis cluster with Multi-AZ Automatic Failover feature set to disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_ELASTIC_CACHE_2

***<font color="white">ID:</font>*** PR-AWS-0056-ACK

***Title: [AWS ElastiCache Redis cluster with Redis AUTH feature disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_ELASTIC_CACHE_3

***<font color="white">ID:</font>*** PR-AWS-0057-ACK

***Title: [AWS ElastiCache Redis cluster with encryption for data at rest disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_ELASTIC_CACHE_4

***<font color="white">ID:</font>*** PR-AWS-0058-ACK

***Title: [AWS ElastiCache Redis cluster with in-transit encryption disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_ELASTIC_SEARCH_1

***<font color="white">ID:</font>*** PR-AWS-0074-ACK

***Title: [AWS ElasticSearch cluster not in a VPC]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_ELASTIC_SEARCH_2

***<font color="white">ID:</font>*** PR-AWS-0076-ACK

***Title: [AWS Elasticsearch domain Encryption for data at rest is disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_ELASTIC_SEARCH_3

***<font color="white">ID:</font>*** PR-AWS-0077-ACK

***Title: [AWS Elasticsearch domain has Dedicated master set to disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_ELASTIC_SEARCH_4

***<font color="white">ID:</font>*** PR-AWS-0080-ACK

***Title: [AWS Elasticsearch domain has Zone Awareness set to disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_RDS_1

***<font color="white">ID:</font>*** PR-AWS-0121-ACK

***Title: [AWS RDS database instance is publicly accessible]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_RDS_2

***<font color="white">ID:</font>*** PR-AWS-0125-ACK

***Title: [AWS RDS instance is not encrypted]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_RDS_3

***<font color="white">ID:</font>*** PR-AWS-0127-ACK

***Title: [AWS RDS instance with Multi-Availability Zone disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_RDS_4

***<font color="white">ID:</font>*** PR-AWS-0128-ACK

***Title: [AWS RDS instance with copy tags to snapshots disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_RDS_5

***<font color="white">ID:</font>*** PR-AWS-0129-ACK

***Title: [AWS RDS instance without Automatic Backup setting]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_RDS_6

***<font color="white">ID:</font>*** PR-AWS-0130-ACK

***Title: [AWS RDS minor upgrades not enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_RDS_7

***<font color="white">ID:</font>*** PR-AWS-0131-ACK

***Title: [AWS RDS retention policy less than 7 days]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_SNS_1

***<font color="white">ID:</font>*** PR-AWS-0153-ACK

***Title: [AWS SNS topic encrypted using default KMS key instead of CMK]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** TEST_SNS_2

***<font color="white">ID:</font>*** PR-AWS-0154-ACK

***Title: [AWS SNS topic with server-side encryption disabled]***

----------------------------------------------------


[AWS API Gateway endpoints without client certificate authentication]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/ack/all/PR-AWS-0002-ACK.md
[AWS DynamoDB encrypted using AWS owned CMK instead of AWS managed CMK]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/ack/all/PR-AWS-0036-ACK.md
[AWS ElastiCache Redis cluster with Multi-AZ Automatic Failover feature set to disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/ack/all/PR-AWS-0055-ACK.md
[AWS ElastiCache Redis cluster with Redis AUTH feature disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/ack/all/PR-AWS-0056-ACK.md
[AWS ElastiCache Redis cluster with encryption for data at rest disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/ack/all/PR-AWS-0057-ACK.md
[AWS ElastiCache Redis cluster with in-transit encryption disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/ack/all/PR-AWS-0058-ACK.md
[AWS ElasticSearch cluster not in a VPC]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/ack/all/PR-AWS-0074-ACK.md
[AWS Elasticsearch domain Encryption for data at rest is disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/ack/all/PR-AWS-0076-ACK.md
[AWS Elasticsearch domain has Dedicated master set to disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/ack/all/PR-AWS-0077-ACK.md
[AWS Elasticsearch domain has Zone Awareness set to disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/ack/all/PR-AWS-0080-ACK.md
[AWS RDS database instance is publicly accessible]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/ack/all/PR-AWS-0121-ACK.md
[AWS RDS instance is not encrypted]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/ack/all/PR-AWS-0125-ACK.md
[AWS RDS instance with Multi-Availability Zone disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/ack/all/PR-AWS-0127-ACK.md
[AWS RDS instance with copy tags to snapshots disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/ack/all/PR-AWS-0128-ACK.md
[AWS RDS instance without Automatic Backup setting]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/ack/all/PR-AWS-0129-ACK.md
[AWS RDS minor upgrades not enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/ack/all/PR-AWS-0130-ACK.md
[AWS RDS retention policy less than 7 days]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/ack/all/PR-AWS-0131-ACK.md
[AWS SNS topic encrypted using default KMS key instead of CMK]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/ack/all/PR-AWS-0153-ACK.md
[AWS SNS topic with server-side encryption disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/ack/all/PR-AWS-0154-ACK.md
