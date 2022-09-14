



# Master Test ID: PR-AZR-TRF-ARC-001


Master Snapshot Id: ['TRF_TEMPLATE_SNAPSHOT']

type: rego

rule: [file(Redis.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AZR-TRF-ARC-001|
|eval: |data.rule.enableSslPort|
|message: |data.rule.enableSslPort_err|
|remediationDescription: |In 'azurerm_redis_cache' resource, set 'enable_non_ssl_port = false' or remove 'enable_non_ssl_port' property to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_cache#enable_non_ssl_port' target='_blank'>here</a> for details.|
|remediationFunction: |PR_AZR_TRF_ARC_001.py|


severity: High

title: Ensure that the Redis Cache accepts only SSL connections

description: It is recommended that Redis Cache should allow only SSL connections. Note: some Redis tools (like redis-cli) do not support SSL. When using such tools plain connection ports should be enabled.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |git|
|compliance: |['PCI-DSS', 'GDPR', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice']|
|service: |['terraform']|


resourceTypes: ['azurerm_redis_linked_server', 'azurerm_redis_cache']


[file(Redis.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/Redis.rego
