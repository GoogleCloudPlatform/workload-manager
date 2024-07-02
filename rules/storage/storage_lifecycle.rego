# Copyright 2024 Google LLC
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     https://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

########################################################################
# DETAILS:  SetStorageClass lifecycle rules MUST have allowed classification.
# SEVERITY: High
# ASSET_TYPE: storage.googleapis.com/Bucket
# TAGS: Cloud Storage, Operations, Reliability, Manageability
########################################################################

package templates.google.storage.lifecycle

import data.validator.google.lib as lib
import data.validator.google.lib.parameters as gparam
import future.keywords

asset := input.asset

asset_type := "storage.googleapis.com/Bucket"

params := lib.get_default(gparam.global_parameters, "cloud_storage", {})

deny[{
	"msg": "SetStorageClass lifecycle rules must have allowed classifications.",
	"details": {"name": asset.name},
}] {

	# Check if resource is in exempt list
	exempt_list := lib.get_default(params, "exemptions", [])
	exempt := {asset.name} & {ex | ex := exempt_list[_]}
	not count(exempt) != 0

	# List of allowed classifications from parameters
	allowedClassifications := lib.get_default(params, "lifecycle_rule_class_classification", [])

	action = asset.resource.data.lifecycle.rule[_].action

	# This specific type of action must be present in the allowed list above
	action.type == "SetStorageClass"
	not lib.get_default(action, "storageClass", "") in allowedClassifications
}
