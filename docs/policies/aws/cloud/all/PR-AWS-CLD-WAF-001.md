



# Master Test ID: PR-AWS-CLD-WAF-001


Master Snapshot Id: ['TEST_ALL_01']

type: rego

rule: [file(all.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-WAF-001|
|eval: |data.rule.waf_log4j_vulnerability|
|message: |data.rule.waf_log4j_vulnerability_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-managedrulegroupstatement.html#cfn-wafv2-webacl-managedrulegroupstatement-name' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_WAF_001.py|


severity: High

title: JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration

description: Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['waf']|



[file(all.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
