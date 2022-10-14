



# Title: AWS ElastiCache Redis cluster with Multi-AZ Automatic Failover feature set to disabled


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-EC-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-EC-001|
|eval|data.rule.cache_failover|
|message|data.rule.cache_failover_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_replication_group' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_EC_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies ElastiCache Redis clusters which have Multi-AZ Automatic Failover feature set to disabled. It is recommended to enable the Multi-AZ Automatic Failover feature for your Redis Cache cluster, which will improve primary node reachability by providing read replica in case of network connectivity loss or loss of availability in the primary's availability zone for read/write operations._x005F_x000D_ Note: Redis cluster Multi-AZ with automatic failover does not support T1 and T2 cache node types and is only available if the cluster has at least one read replica.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CMMC', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 34", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.183', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SI.2.216', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:10.a', 'LGPD', 'MAS TRM', 'MAS TRM 2021-7.2.1', 'MAS TRM 2021-7.2.2', 'MLPS', 'MLPS 2.0-8.1.4.9', 'NIST 800', 'NIST 800-53 Rev 5-Predictable Failure Prevention \| Failover Capability', 'NIST 800-53 Rev4-SI-13 (5)', 'NIST CSF', 'NIST CSF-PR.MA-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.7.1', 'NIST SP 800-172-3.4.1e', 'NIST SP 800-172-3.4.2e', 'PCI DSS v3.2.1-6.3', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_elasticache_replication_group']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego
