package metadata

remap: functions: redact: {
	arguments: [
		{
			name:        "value"
			description: "The value that you want to redact."
			required:    true
			type: ["string"]
		},
		{
			name:        "filters"
			description: "A list of filters to apply"
			required:    false
			type: ["array"]
			enum: {
				pattern: "Filter based on a supplied regular expression."
			}
		},
		{
			name:        "redactor"
			description: "The redaction method to be applied, with multiple options available."
			required:    false
			type: ["string"]
			enum: {
				full: "Replace the entire content with `****`."
			}
		},
		{
			name: "patterns"
			description: """
				A list of patterns to apply. Patterns can be strings or regular expressions; if a
				string is supplied, Vector searches for exact matches when redacting.
				"""
			required: false
			type: ["array"]
		},
	]
	return: ["string"]
	category: "text"
	description: """
		Obscures sensitive data.
		"""
	examples: [
		{
			title: "Redact credit card number"
			input: {
				credit_card: "9876123454320123"
				filters: ["pattern"]
				redactor: "full"
				patterns: ["[0-9]{16}"]
			}
			source: """
				.credit_card = redact(.credit_card, filters = ["pattern"], redactor = "full", patterns = ["[0-9]{16}"])
				"""
			output: {
				credit_card: "****"
			}
		},
	]
}
