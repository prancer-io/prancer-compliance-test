



# Title: Ensure AWS ElastiCache cluster is associated with VPC.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-EC-010

***<font color="white">Master Snapshot Id:</font>*** ['TEST_EC_01', 'TEST_EC']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-EC-010|
|eval|data.rule.cache_cluster_vpc|
|message|data.rule.cache_cluster_vpc_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elasticache.html#ElastiCache.Client.describe_replication_groups' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_EC_010.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It identifies ElastiCache Clusters which are not associated with VPC. It is highly recommended to associate ElastiCache with VPC, as provides virtual network in your own logically isolated area and features such as selecting IP address range, creating subnets, and configuring route tables, network gateways, and security settings. NOTE: If you created your AWS account before 2013-12-04, you might have support for the EC2-Classic platform in some regions. AWS has deprecated the use of Amazon EC2-Classic for launching ElastiCache clusters. All current generation nodes are launched in Amazon Virtual Private Cloud only. So this policy only applies legacy ElastiCache clusters which are created using EC2-Classic.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'LGPD', 'CSA CCM', 'CCPA', 'CMMC', "CyberSecurity Law of the People's Republic of China", 'HITRUST', 'ISO/IEC 27002', 'ISO/IEC 27017', 'ISO/IEC 27018', 'MAS TRM', 'MLPS', 'NIST 800', 'NIST CSF', 'NIST SP', 'PCI DSS', 'PIPEDA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'AWS Well-Architected Framework-Infrastructure Protection', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CCPA 2018-1798.150(a)(1)', 'CSA CCM v.4.0.1-DSP-07', 'CSA CCM v.4.0.1-DSP-10', 'CSA CCM v.4.0.1-DSP-17', 'CSA CCM v.4.0.1-IVS-03', 'CSA CCM v.4.0.1-UEM-11', "CyberSecurity Law of the People's Republic of China-Article 21", "CyberSecurity Law of the People's Republic of China-Article 25", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.183', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SI.2.216', 'HITRUST v.9.4.2-Control Reference:09.m', 'ISO/IEC 27002:2013-12.2.1', 'ISO/IEC 27002:2013-12.3.1', 'ISO/IEC 27002:2013-13.1.1', 'ISO/IEC 27002:2013-13.1.2', 'ISO/IEC 27002:2013-13.1.3', 'ISO/IEC 27002:2013-13.2.1', 'ISO/IEC 27002:2013-13.2.3', 'ISO/IEC 27002:2013-14.1.1', 'ISO/IEC 27002:2013-14.2.5', 'ISO/IEC 27002:2013-18.1.3', 'ISO/IEC 27002:2013-18.1.4', 'ISO/IEC 27002:2013-8.3.1', 'ISO/IEC 27002:2013-8.3.3', 'ISO/IEC 27017:2015-6.1.1', 'ISO/IEC 27018:2019-10.1.2', 'ISO/IEC 27018:2019-12.3.1', 'MAS TRM 2021-7.2.1', 'MAS TRM 2021-7.2.2', 'MLPS 2.0-8.1.2.1', 'NIST 800-53 Rev 5-Boundary Protection \| Connections to Public Networks', 'NIST 800-53 Rev4-CA-3 (4)', 'NIST CSF-PR.AC-5', 'NIST CSF-PR.DS-5', 'NIST CSF-PR.PT-4', 'NIST SP 800-171 Revision 2-3.13.5', 'NIST SP 800-172-3.13.4e', 'PCI DSS v3.2.1-1.3.6', 'PIPEDA-4.7.3']|
|service|['elasticache']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
