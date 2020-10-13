package metadata

components: sources: logplex: {
	_port: 80

	title:             "Heroku Logplex"
	short_description: "Ingests data through the [Heroku Logplex HTTP Drain protocol][urls.logplex_protocol] and outputs log events."
	long_description:  "[Heroku’s Logplex][urls.logplex] router is responsible for collating and distributing the log entries generated by Heroku apps and other components of the Heroku platform. It makes these entries available through the Logplex public API and the Heroku command-line tool."

	classes: {
		commonly_used: false
		deployment_roles: ["aggregator"]
		egress_method: "batch"
		function:      "receive"
	}

	features: {
		checkpoint: enabled: false
		multiline: enabled:  false
		tls: {
			enabled:                true
			can_enable:             true
			can_verify_certificate: true
			enabled_default:        false
		}
	}

	statuses: {
		delivery:    "at_least_once"
		development: "beta"
	}

	support: {
		platforms: {
			docker: ports: [_port]
			triples: {
				"aarch64-unknown-linux-gnu":  true
				"aarch64-unknown-linux-musl": true
				"x86_64-apple-darwin":        true
				"x86_64-pc-windows-msv":      true
				"x86_64-unknown-linux-gnu":   true
				"x86_64-unknown-linux-musl":  true
			}
		}

		requirements: [
			"""
				This component exposes a configured port. You must ensure your network allows access to this port.
				""",
		]
		warnings: []
		notices: []
	}

	configuration: {
		address: sources.http.configuration.address
		auth:    sources.http.configuration.auth
	}

	output: logs: line: {
		description: "An individual event from a batch of events received through an HTTP POST request."
		fields: {
			app_name: {
				description: "The app name field extracted from log message."
				required:    true
				type: string: examples: ["erlang"]
			}
			host: fields._local_host
			message: {
				description: "The message field, containing the plain text message."
				required:    true
				type: string: examples: ["Hi from erlang"]
			}
			proc_id: {
				description: "The procid field extracted from log message."
				required:    true
				type: string: examples: ["console"]
			}
			timestamp: fields._current_timestamp
		}
	}
}
