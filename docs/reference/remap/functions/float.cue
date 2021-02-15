package metadata

remap: functions: float: {
	category: "Type"
	description: """
		Errors if `value` is not a float, if `value` is a float it is returned.

		This allows the type checker to guarantee that the returned value is a float and can be used in any function
		that expects this type.
		"""

	arguments: [
		{
			name:        "value"
			description: "The value to ensure is a float."
			required:    true
			type: ["any"]
		},
	]
	internal_failure_reasons: [
		"`value` is not a float.",
	]
	return: {
		types: ["float"]
		rules: [
			#"If `value` is an float then it is returned."#,
			#"Otherwise an error is raised."#,
		]
	}
	examples: [
		{
			title: "Float"
			input: log: {
				radius: 42
			}
			source: #"""
				radius = float!(.radius)
				3.14 * radius * radius
				"""#
			return: 5538.96
		},
	]
}
