Copyright 2024 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

########################################################################
# DETAILS:  MUST have atleast one tag
# SEVERITY: Medium
# ASSET_TYPE: compute.googleapis.com/Instance
# TAGS: Tags, Cost, Management, Compute Engine
########################################################################

package templates.google.compute.instance.tags

import data.validator.google.lib as lib
import data.validator.google.lib.parameters as gparam
import future.keywords

asset_type = "compute.googleapis.com/Instance"

asset := input.asset

params:= lib.get_default(gparam.global_parameters,"compute",{})

deny [{"msg": message, "details": metadata}] {

	# Check if resource is in exempt list
	exempt_list := lib.get_default(params, "exemptions", [])
	exempt := {asset.name} & {ex | ex := exempt_list[_]}
	not count(exempt) != 0

	tags := lib.get_default(asset.resource.data, "tags", {"items": []})
	count(tags.items) == 0

	message:=sprintf("{'Asset-type': '%v}. Missing all tags. Current list of tags: %v", [asset_type, tags])

	metadata:={"name": asset.name}
}
