package metadata

remap: functions: strlen: {
	category: "Enumerate"
	description: """
		Returns the number of UTF-8 characters in `value`. This differs from
		`length` which would count the number of bytes of a string.

		Note that this is the count of [unicode scalar values](https://www.unicode.org/glossary/#unicode_scalar_value)
		which can sometimes differ from [unicode code points](https://www.unicode.org/glossary/#code_point).
		"""

	arguments: [
		{
			name:        "value"
			description: "The string"
			required:    true
			type: ["string"]
		},
	]
	internal_failure_reasons: []
	return: {
		types: ["integer"]
	}

	examples: [
		{
			title: "strlen"
			source: """
				strlen("ñandú")
				"""
			return: 5
		},
	]
}
