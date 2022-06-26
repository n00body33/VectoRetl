package metadata

remap: functions: get_enrichment_table_record: {
	category:    "Enrichment"
	description: """
		Searches an [enrichment table](\(urls.enrichment_tables_concept)) for a row that matches the
		provided condition. A single row must be matched. If either no rows or more than one row is
		found, an error is returned.

		\(remap._enrichment_table_explainer)
		"""

	arguments: [
		{
			name:        "table"
			description: "The [enrichment table](\(urls.enrichment_tables_concept)) to search."
			required:    true
			type: ["string"]
		},
		{
			name: "condition"
			description: """
				The condition to search on. Since the condition is used at boot time to create
				indices into the data, these conditions must be statically defined.
				"""
			required: true
			type: ["object"]
		},
		{
			name: "select"
			description: """
				A subset of fields from the enrichment table to return. If not specified,
				all fields are returned.
				"""
			required: false
			type: ["array"]
		},
		{
			name:        "case_sensitive"
			description: "Should text fields match case exactly."
			required:    false
			type: ["boolean"]
			default: true
		},
	]
	internal_failure_reasons: [
		"The row isn't found",
		"Multiple rows are found that match the condition",
	]
	return: types: ["object"]

	examples: [
		{
			title: "Exact match"
			source: #"""
				get_enrichment_table_record!("test",
				  {
				    "surname": "bob",
				    "firstname": "John"
				  },
				  case_sensitive: false)
				"""#
			return: {"id": 1, "firstname": "Bob", "surname": "Smith"}
		},
		{
			title: "Date range search"
			source: #"""
				get_enrichment_table_record!("test",
				  {
				    "surname": "Smith",
				    "date_of_birth": {
				      "from": t'1985-01-01T00:00:00Z',
				      "to": t'1985-12-31T00:00:00Z'
				    }
				  })
				"""#
			return: {"id": 1, "firstname": "Bob", "surname": "Smith"}
		},
		{
			title: "Geoip table"
			source: #"""
				get_enrichment_table_record!("test",
				  {
					"ip": .ip,
				  })
				"""#
			return: {"city_name": "New York", "continent_code": "NA", "country_code": "US", "country_name": "United States", "region_code": null, "region_name": null, "metro_code": 501, "latitude": 40.76241, "longitude": -73.97436020807207, "postal_code": null, "timezone": null}
		},
	]
}
