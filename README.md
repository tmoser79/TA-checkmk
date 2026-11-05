# Splunk Add-on for Checkmk (`TA-checkmk`)

Technology add-on for onboarding **Checkmk logs and monitoring alerts** into
Splunk Enterprise or Splunk Cloud. There is no Splunk-supported Checkmk TA on
Splunkbase; this package is the knowledge layer, file inputs, optional REST
poller, and CIM Alerts mapping.

The Checkmk-side HEC notification plugin lives next to this folder in
[`../checkmk_splunk_hec`](../checkmk_splunk_hec).

## What it does

| Stream | Sourcetype | How it arrives | CIM |
| --- | --- | --- | --- |
| Notifications (PROBLEM/RECOVERY/ACK/…) | `checkmk:alert` | Checkmk plugin → Splunk HEC | Alerts |
| Event Console forwards | `checkmk:ec` | HEC JSON | Alerts |
| REST status snapshot (optional) | `checkmk:status` | Modular input on a Heavy Forwarder | Alerts |
| CMC history / Raw `nagios.log` | `checkmk:history` | Universal Forwarder | Alerts for `SERVICE ALERT`, `HOST ALERT`, notifications |
| `notify.log` / `mknotifyd.log` | `checkmk:notify`, `checkmk:mknotifyd` | UF | — |
| `cmc.log` | `checkmk:cmc` | UF | — |
| `web.log` | `checkmk:web` | UF | — |
| `security.log` | `checkmk:security` | UF | — |
| Event Console daemon | `checkmk:eventconsole` | UF | — |
| Site Apache access/error | `apache:access:combined`, `apache:error` | UF + Splunk Add-on for Apache | Web |

`host` on the event is the Checkmk server (or HEC sender). The **monitored**
device is `dest` / `dest_host`. That is the correct CIM Alerts split.

## Architecture

```
Checkmk site
  ├─ notification plugin ──HTTPS──► Splunk HEC ──► index=checkmk sourcetype=checkmk:alert
  └─ site log files      ──UF/S2S─► indexers     ──► sourcetype=checkmk:*

Search heads: TA-checkmk + Splunk_SA_CIM (Alerts)
```

Do **not** use Checkmk’s built-in “Splunk On-Call” method for this. That pages
VictorOps. Do **not** use Checkmk’s Splunk special agent; that monitors Splunk
from Checkmk.

## Install on Splunk

1. Create index `checkmk` (Cloud: Settings → Indexes). This add-on does not
   ship `indexes.conf`, so it stays Cloud-safe.
2. Install `TA-checkmk` on search heads (required), indexers (required if UFs
   send unparsed files), and the Universal Forwarder on the Checkmk host.
3. Install [Splunk Common Information Model](https://splunkbase.splunk.com/app/1621)
   on search heads.
4. Optional: [Splunk Add-on for Apache Web Server](https://splunkbase.splunk.com/app/3185)
   if you collect site Apache logs, and
   [Splunk Add-on for Unix and Linux](https://splunkbase.splunk.com/app/833)
   for the Checkmk **server OS** only.

Package from this folder:

```bash
./pack.sh
```

Copy `local/inputs.conf` on the Checkmk Universal Forwarder from the disabled
examples in `default/inputs.conf` and set `disabled = 0` for the files you
want. Site logs are usually mode `0600`; grant the Splunk user read access.

Skip `core/archive` unless you need a one-time backfill. History volume is
license-sensitive.

## Install the notification plugin on Checkmk

See [`../checkmk_splunk_hec/README.md`](../checkmk_splunk_hec/README.md).
Minimum: copy `splunk_hec` to `~/local/share/check_mk/notifications/`, make it
executable, add a notification rule with HEC URL + token.

## CIM Alerts fields

| CIM field | Checkmk source |
| --- | --- |
| `app` | `checkmk` |
| `vendor_product` | `Checkmk` |
| `type` | `alert` (history downtime/ack/flap → `event`) |
| `dest` / `dest_host` | Host name |
| `dest_ip` | Host address when it is an IP |
| `signature` | Service description, or `Host Check` |
| `signature_id` | Check command |
| `vendor_severity` | `CRIT` / `CRITICAL` / `DOWN` / `WARN` / … |
| `severity` | `critical`, `high`, `medium`, `low`, `informational` |
| `id` | Problem ID, or a stable hash of the history line |
| `description` / `body` | Plugin output |
| `user` | Contact / acknowledgement author |
| `src` | Checkmk monitoring host |

Event type `checkmk_alert` is tagged `alert` so Enterprise Security and ITSI
can use `tag=alert`.

Searches:

```
`checkmk_alerts`
`checkmk_problems`
index=checkmk sourcetype=checkmk:alert severity=critical
index=checkmk sourcetype=checkmk:history log_type="SERVICE ALERT"
```

## Sample data (Eventgen)

Eventgen is still the right way to ship **live demo data inside a Splunk TA**.
[SA-Eventgen 8.2.1](https://splunkbase.splunk.com/app/1924) (9 Jul 2025) works with
Splunk 9.1–10.7. Install Eventgen, then enable generation only on a lab instance:

```
# $SPLUNK_HOME/etc/apps/TA-checkmk/local/eventgen.conf
[global]
disabled = false
```

`default/eventgen.conf` is **disabled** so production installs emit nothing.
There is no HEC token in the add-on; output is Splunk’s spool directory.

| Sample | Sourcetype |
| --- | --- |
| `checkmk_alert.sample` | `checkmk:alert` |
| `checkmk_ec.sample` | `checkmk:ec` |
| `checkmk_status.sample` | `checkmk:status` |
| `checkmk_history.sample` | `checkmk:history` |
| `checkmk_notify.sample` | `checkmk:notify` |
| `checkmk_mknotifyd.sample` | `checkmk:mknotifyd` |
| `checkmk_cmc.sample` | `checkmk:cmc` |
| `checkmk_web.sample` | `checkmk:web` |
| `checkmk_security.sample` | `checkmk:security` |
| `checkmk_eventconsole.sample` | `checkmk:eventconsole` |
| `checkmk_alerts_handler.sample` | `checkmk:alerts_handler` |
| `checkmk_dcd.sample` | `checkmk:dcd` |
| `checkmk_liveproxyd.sample` | `checkmk:liveproxyd` |
| `checkmk_apache_access.sample` | `apache:access:combined` |
| `checkmk_apache_error.sample` | `apache:error` |

Tokens rotate hosts, services, contacts, IPv4 addresses, and timestamps.

For **CI field tests** against Docker Splunk, prefer
[pytest-splunk-addon](https://splunk.github.io/pytest-splunk-addon/sample_generator/)
(`pytest-splunk-addon-data.conf`) instead of SA-Eventgen. From addon 1.3.0 that
plugin ingests samples itself. Eventgen remains the in-app generator for a
human lab.

## Optional REST poller

On a Heavy Forwarder, enable `[checkmk_rest://<name>]` as documented in
`README/inputs.conf.spec`. TLS verification defaults to on. This path is for
“what is red right now”; HEC notifications remain the system of record for
alert history.

## Related add-ons (not Checkmk)

| App | Use with this TA? |
| --- | --- |
| Splunk Add-on for Nagios Core (2703) | Only if you insist on `nagios:core` on Raw Edition `nagios.log`. CIM 4.x, last 2020. Prefer `checkmk:history`. |
| Analytics for Nagios (352) | No. Unmaintained Livestatus dashboards from 2015. |
| Splunk Add-on for Unix and Linux (833) | Yes, for the Checkmk host OS. |
| Splunk CIM (1621) | Yes, search heads. |

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

Apache License 2.0. Checkmk and Splunk are trademarks of their respective
owners. This add-on is not affiliated with Checkmk GmbH or Splunk LLC.
