



# Title: AWS ElasticSearch cluster not in a VPC


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-ES-001

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elasticsearch.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-ES-001|
|eval|data.rule.esearch_vpc|
|message|data.rule.esearch_vpc_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_ES_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** VPC support for Amazon ES is easy to configure, reliable, and offers an extra layer of security. With VPC support, traffic between other services and Amazon ES stays entirely within the AWS network, isolated from the public Internet. You can manage network access using existing VPC security groups, and you can use AWS Identity and Access Management (IAM) policies for additional protection. VPC support for Amazon ES domains is available at no additional charge.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::elasticsearch::domain']


[elasticsearch.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/elasticsearch.rego
