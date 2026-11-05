# Optional REST modular input

`checkmk_rest.py` polls the Checkmk REST API on a Heavy Forwarder and writes
`sourcetype=checkmk:status` events. It is disabled until you add a named stanza
in `local/inputs.conf`:

```
[checkmk_rest://mysite]
api_url = https://checkmk.example.com/mysite
username = automation
secret = <automation-secret>
interval = 300
only_problems = 1
verify_tls = 1
index = checkmk
sourcetype = checkmk:status
```

Use a Checkmk automation user with read-only permission for hosts and services.
Do not put the secret in git.

Splunk Cloud self-service install may require private-app vetting before a
custom modular input is allowed to run. File monitors and HEC alerts do not
need this input.
