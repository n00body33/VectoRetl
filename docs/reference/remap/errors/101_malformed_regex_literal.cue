package metadata

remap: errors: "101": {
	title:       "Malformed regex literal"
	description: """
		A [regex literal expression](\(urls.vrl_expressions)#\(remap.literals.regular_expression.anchor)) is malformed
		and does not result in a valid Regular Expression.
		"""
	rationale: """
		Invalid regular expressions will not compile.
		"""
	resolution: """
		Regular expressions are difficult to write and commonly result in syntax errors. If you're parsing a common
		log format then we recommend using one of VRL's [`parse_*` functions](\(urls.vrl_functions)#parsing). If
		you do not see a fucntion for your format please [request it](\(urls.new_feature_request)). Otherwise, use the
		[Rust regex tester](\(urls.regex_tester)) to test and correct your regular expression.
		"""

	examples: [
		{
			"title": "\(title) (common format)"
			source: #"""
				. |= parse_regex!(.message, r'^(?P<host>[\w\.]+) - (?P<user>[\w]+) (?P<bytes_in>[\d]+) \[?P<timestamp>.*)\] "(?P<method>[\w]+) (?P<path>.*)" (?P<status>[\d]+) (?P<bytes_out>[\d]+)$')
				"""#
			raises: compiletime: #"""
				error: \#(title)
				  ┌─ :1:1
				  │
				1 │ 	. |= parse_regex(.message, r'^(?P<host>[\w\.]+) - (?P<user>[\w]+) (?P<bytes_in>[\d]+) \[?P<timestamp>.*)\] "(?P<method>[\w]+) (?P<path>.*)" (?P<status>[\d]+) (?P<bytes_out>[\d]+)$')
				  │                                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
				  │                                │
				  │                                this regular expression is invalid
				  │
				"""#
			diff: #"""
				-. |= parse_regex!(.message, r'^(?P<host>[\w\.]+) - (?P<user>[\w]+) (?P<bytes_in>[\d]+) \[?P<timestamp>.*)\] "(?P<method>[\w]+) (?P<path>.*)" (?P<status>[\d]+) (?P<bytes_out>[\d]+)$')
				+. |= parse_common_log!(.message)
				"""#
		},
	]
}
