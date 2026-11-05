[monitor://<path>]
* Standard Splunk file monitor. See the default/inputs.conf examples.

[checkmk_rest://<name>]
* Poll the Checkmk REST API for current host and service states.
* Intended for a Heavy Forwarder. Splunk Cloud self-service install may
  require private-app vetting before this modular input can run there.

api_url = <value>
* Base URL of the Checkmk site, including the site name.
* Example: https://checkmk.example.com/mysite

username = <value>
* Checkmk automation user name.

secret = <value>
* Checkmk automation secret. Do not commit this value. Prefer a Splunk
  encrypted local/inputs.conf on the collecting instance.

interval = <integer>
* Poll interval in seconds. Default is 300.

only_problems = <value>
* If 1/true/yes, only hosts not UP and services not OK are indexed.
* Default is 1.

verify_tls = <value>
* If 1/true/yes, verify the Checkmk TLS certificate. Default is 1.

index = <value>
* Destination index. Default is checkmk.

sourcetype = <value>
* Destination sourcetype. Default is checkmk:status.
