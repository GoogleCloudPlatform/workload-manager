# Google Rego Rules for Workload Manager: Custom rules

This repository contains sample rules that you can use with the Workload Manager product. You can use these rules as an inspiration to craft validation rules suitable for your own organizational needs.

If you need additional help in crafting more specific custom rules, please engage with your account teams who will help you navigate this request.

Rego Rule Template:

Ensure appropriate metadata are defined for each Rego rule.
In our example we use parameters.rego file for managing parameters for Rego rules centrally. you can choose to directly write self contained Rego policy.

**Policy Template **:
```
#########################################
# DETAILS: <Description>  
# SEVERITY: High | Medium | Low
# ASSET_TYPE: compute.googleapis.com/Instance <- REQUIRED
# TAGS: Inventory Management, Compliance, Cost
#########################################

#Import statements
import data.validator.gcp.lib as lib
import data.validator.gcp.lib.parameters as gparam
import future.keywords

# Get inital values for policy example values from parameters.rego file
params := lib.get_default(gparam.global_parameters, "compute", {})

# This deny block allows you to define the  violation criteria.
# you can define multiple deny blocks each acting as Logical OR to produce violation.  
deny[{
  #message here can be a string
  "msg": message,
  #metadata here is a map and only supports name key.
  "details": metadata,
}] {

  # your REGO logic here to validate if certain configs are in violation.

  message := sprintf("VM instance %v is missing required labels: %v", [input.asset.name, lables])
  metadata := {"name": input.asset.name}
}

deny[{ "msg": message, "details": metadata,}]
  {
    #Another logic for deny block.
  }

```
TAGS: You can add as many tags as possible, these tags will help filter rules by tags. Example "Compute".

Refer Supported asset types and configs you can validate from CAI asset: https://cloud.google.com/asset-inventory/docs/supported-asset-types

*High-level workflow:*

1. Download sample policies in your local environment.
1. Customize /lib/parameters.rego with appropriate values/settings or create new rules based on sample policies.
   1. Note: Ensure rules names are unique across your bucket.
1. Upload these rules to a Cloud Storage bucket that you can access from  Workload Manager.
   1. If you're using Rego files directly, ensure that the /lib folder exists and only library functions are added in this folder.
   1. Under the subfolders, you can organize the rules however you want to.
1. Create a new evaluation, select 'General' as the workload type, and  then select the bucket with rego rules from step 3.
1. [Optional] You can configure BigQuery export for each evaluation. Ensure BQ Dataset is regional and in supported regions where Workload Manager is allowed to run evaluations.
1. Select scope for this evaluation project/s.
1. Select Rules you want to use in the evaluation.
1. [Optional] Select Scheduled frequency of the scan.
1. [Optional] Select notification channel (Google Chat, email, pub/sub, etc)
1. Click create.
1. If a schedule is not set, you can go to this evaluation and run an on-demand scan.
1. Evaluation results will show up on the UI. Workload Manager maintains a historical record for each scan. You can see the same results in BigQuery exports if configured.
