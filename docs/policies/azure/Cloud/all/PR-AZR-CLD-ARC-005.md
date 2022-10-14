



# Title: Configure Azure Cache for redis with private endpoints


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-ARC-005

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_420', 'AZRSNP_500']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([Redis.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-ARC-005|
|eval|data.rule.arc_private_endpoint|
|message|data.rule.arc_private_endpoint_err|
|remediationDescription|To create a private endpoint, follow these steps:<br><br>1. In the Azure portal, search for Azure Cache for Redis. Then, press enter or select it from the search suggestions.<br>2. Select the cache instance you want to add a private endpoint to.<br>3. On the left side of the screen, select Private Endpoint.<br>4. Select the Private Endpoint button to create your private endpoint.<br>5. On the Create a private endpoint page, configure the settings for your private endpoint.<br>6. Select the Next: Resource button at the bottom of the page.<br>7. In the Resource tab, select your subscription, choose the resource type as Microsoft.Cache/Redis, and then select the cache you want to connect the private endpoint to.<br>8. Select the Next: Configuration button at the bottom of the page.<br>9. In the Configuration tab, select the virtual network and subnet you created in the previous section.<br>10. Select the Next: Tags button at the bottom of the page.<br>11. Optionally, in the Tags tab, enter the name and value if you wish to categorize the resource.<br>12. Select Review + create. You're taken to the Review + create tab where Azure validates your configuration.<br>13. After the green Validation passed message appears, select Create.|
|remediationFunction|PR_AZR_CLD_ARC_005.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Azure Private Link lets you connect your virtual network to Azure services without a public IP address at the source or destination. The Private Link platform handles the connectivity between the consumer and services over the Azure backbone network. By mapping private endpoints to your cache for redis, data leakage risks are reduced. Learn more about private links at - https://aka.ms/azureprivatelinkoverview  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['Best Practice']|
|service|['Databases']|



[Redis.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/Redis.rego
