package metadata

components: sources: nginx_metrics: {
	title:       "Nginx Metrics"
	description: "[Nginx][urls.nginx] is an HTTP and reverse proxy server, a mail proxy server, and a generic TCP/UDP proxy server."

	classes: {
		commonly_used: false
		delivery:      "at_least_once"
		deployment_roles: ["daemon", "sidecar"]
		development:   "beta"
		egress_method: "batch"
	}

	features: {
		collect: {
			checkpoint: enabled: false
			from: {
				service: {
					name:     "Nginx Server"
					thing:    "a \(name)"
					url:      urls.nginx
					versions: null
				}

				interface: {
					socket: {
						api: {
							title: "Nginx ngx_http_stub_status_module module"
							url:   urls.nginx_stub_status_module
						}
						direction: "outgoing"
						protocols: ["http"]
						ssl: "optional"
					}
				}
			}
		}
		multiline: enabled: false
	}

	support: {
		platforms: {
			"aarch64-unknown-linux-gnu":  true
			"aarch64-unknown-linux-musl": true
			"x86_64-apple-darwin":        true
			"x86_64-pc-windows-msv":      true
			"x86_64-unknown-linux-gnu":   true
			"x86_64-unknown-linux-musl":  true
		}

		requirements: [
			"Module `ngx_http_stub_status_module` should be enabled.",
		]

		warnings: []
		notices: []
	}

	configuration: {
		endpoints: {
			description: "HTTP/HTTPS endpoint to Nginx server with enabled `ngx_http_stub_status_module` module."
			required:    true
			type: array: {
				items: type: string: examples: ["http://localhost:8000/basic_status"]
			}
		}
		scrape_interval_secs: {
			description: "The interval between scrapes."
			common:      true
			required:    false
			type: uint: {
				default: 15
				unit:    "seconds"
			}
		}
		namespace: {
			description: "The namespace of metrics. Disabled if empty."
			common:      false
			required:    false
			type: string: default: "nginx"
		}
		tls: configuration._tls_connect & {_args: {
			can_enable:             true
			can_verify_certificate: true
			can_verify_hostname:    true
			enabled_default:        false
		}}
		auth: configuration._http_auth & {_args: {
			password_example: "${HTTP_PASSWORD}"
			username_example: "${HTTP_USERNAME}"
		}}
	}

	how_it_works: {
		mod_status: {
			title: "Module `ngx_http_stub_status_module`"
			body: """
				The [ngx_http_stub_status_module][urls.nginx_stub_status_module]
				module provides access to basic status information. Basic status
				information is a simple web page with text data.
				"""
		}
	}

	telemetry: metrics: {
		collect_completed_total:      components.sources.internal_metrics.output.metrics.collect_completed_total
		collect_duration_nanoseconds: components.sources.internal_metrics.output.metrics.collect_duration_nanoseconds
		request_error_total:          components.sources.internal_metrics.output.metrics.request_error_total
		parse_errors_total:           components.sources.internal_metrics.output.metrics.parse_errors_total
	}

	output: metrics: {
		up: {
			description:       "If the Nginx server is up or not."
			type:              "gauge"
			default_namespace: "nginx"
		}
		connections_active: {
			description:       "The current number of active client connections including `Waiting` connections."
			type:              "gauge"
			default_namespace: "nginx"
		}
		connections_accepted_total: {
			description:       "The total number of accepted client connections."
			type:              "counter"
			default_namespace: "nginx"
		}
		connections_handled_total: {
			description:       "The total number of handled connections. Generally, the parameter value is the same as `accepts` unless some resource limits have been reached (for example, the `worker_connections` limit)."
			type:              "counter"
			default_namespace: "nginx"
		}
		http_requests_total: {
			description:       "The total number of client requests."
			type:              "counter"
			default_namespace: "nginx"
		}
		connections_reading: {
			description:       "The current number of connections where nginx is reading the request header."
			type:              "gauge"
			default_namespace: "nginx"
		}
		connections_writing: {
			description:       "The current number of connections where nginx is writing the response back to the client."
			type:              "gauge"
			default_namespace: "nginx"
		}
		connections_waiting: {
			description:       "The current number of idle client connections waiting for a request."
			type:              "gauge"
			default_namespace: "nginx"
		}
	}
}
