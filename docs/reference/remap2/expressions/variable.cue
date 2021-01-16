package metadata

remap2: expressions: variable: {
	title: "Variable"
	description: """
		A "variable" expression names variables. A variable is a sequence of one or more letters and digits. The first
		character in a variable must be a letter.
		"""
	return: """
		Returns the value of the variable.
		"""

	grammar: {
		source: """
			first ~ (trailing)*
			"""
		definitions: {
			first: {
				description: """
					The `first` character can only be an alpha-numeric character (`a-zA-Z0-9`).
					"""
			}
			trailing: {
				description: """
					The `trailing` characters must only contain ASCII alpha-numeric and underscore characters
					(`a-zA-Z0-9_`).
					"""
			}
		}
	}
}
