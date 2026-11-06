# Checkmk notification plugin (copy onto the site)

This folder ships **inside** `TA-checkmk`. A Splunk admin copies the files onto
the Checkmk site. Checkmk then runs the script when a notification rule fires.

You do **not** need this plugin if you only collect the core history file
(`checkmk:history`). History already records `HOST NOTIFICATION` /
`SERVICE NOTIFICATION` lines. Use this plugin when you want CIM JSON pushed to
Splunk HEC as `checkmk:alert`.

## Files

| File in this folder | Destination on the Checkmk site |
| --- | --- |
| `notifications/splunk_hec` | `~/local/share/check_mk/notifications/splunk_hec` |
| `rulesets/splunk_hec.py` | `~/local/lib/python3/cmk_addons/plugins/splunk_hec/rulesets/splunk_hec.py` |

The ruleset `name` must stay `splunk_hec`, matching the script filename.

After you install the add-on on Splunk, the same files are also under
`$SPLUNK_HOME/etc/apps/TA-checkmk/checkmk/`.

## Install

```bash
SITE=mysite
APP="${SPLUNK_HOME:-.}/etc/apps/TA-checkmk/checkmk"

install -d -m 755 /omd/sites/$SITE/local/share/check_mk/notifications
install -m 755 "$APP/notifications/splunk_hec" \
  /omd/sites/$SITE/local/share/check_mk/notifications/splunk_hec

install -d -m 755 \
  /omd/sites/$SITE/local/lib/python3/cmk_addons/plugins/splunk_hec/rulesets
install -m 644 "$APP/rulesets/splunk_hec.py" \
  /omd/sites/$SITE/local/lib/python3/cmk_addons/plugins/splunk_hec/rulesets/splunk_hec.py

su - $SITE -c 'omd restart apache'
```

On Checkmk versions that still show a free-text parameter list instead of the
form, pass five strings in order: HEC URL, token, index, sourcetype, `yes`/`no`
for TLS verify.

## Splunk HEC

1. Settings → Data inputs → HTTP Event Collector → New token.
2. Enable JSON, index `checkmk`, sourcetype `checkmk:alert`.
3. Put the token in the Checkmk password store. In the notification parameters
   use `store <password_id>` rather than pasting the token.

## Notification rule

Setup → Events → Notifications:

- Notification method: **Splunk HTTP Event Collector**
- HEC URL: `https://splunk.example.com:8088/services/collector/event`
- Prefer the notification spooler (async) so a slow HEC cannot stall the core.

Test with a host/service test notification and confirm:

```
index=checkmk sourcetype=checkmk:alert
```

`~/var/log/notify.log` should show HTTP 200 and plugin exit code 0.

## Payload

The plugin sends CIM Alerts fields (`app`, `dest`, `id`, `severity`,
`signature`, `type`, `vendor_product`, `vendor_severity`, `description`) plus
Checkmk extras (`what`, `site`, `notification_type`, `check_command`).
The HEC token is never written to the event.
