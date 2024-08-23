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

package validator.google.lib

# has_field returns whether an object has a field
has_field(object, field) {
	object[field]
}

# False is a tricky special case, as false responses would create an undefined document unless
# they are explicitly tested for
has_field(object, field) {
	object[field] == false
}

has_field(object, field) = false {
	not object[field]
	not object[field] == false
}

# get_default returns the value of an object's field or the provided default value.
# It avoids creating an undefined state when trying to access an object attribute that does
# not exist
get_default(object, field, _default) = output {
	has_field(object, field)
	output = object[field]
}

get_default(object, field, _default) = output {
	has_field(object, field) == false
	output = _default
}

#this function will check for no-labels and missing labels from input parameters
#params input is a set like {"a","b"}

check_label(resource_input, params) = output {
	count(resource_input) == 0
	output := sprintf("No label detected, Ensure appropriate labels including must-have labels (%v) are applied.", [params])
}
else = output {
	actual_labels:= {x|x:=resource_input[_]["key"]}
	missing := params - actual_labels
	count(missing) != 0
	output := sprintf("Missing must-have labels: %v. Labels detected: %v .", [missing, actual_labels])
}
