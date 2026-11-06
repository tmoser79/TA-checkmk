#!/usr/bin/env python3
"""Checkmk 2.3/2.4 notification parameter form for splunk_hec.

Install next to the notification script so the names match:

  ~/local/share/check_mk/notifications/splunk_hec
  ~/local/lib/python3/cmk_addons/plugins/splunk_hec/rulesets/splunk_hec.py

Then restart the site Apache (omd restart apache).
"""

from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    SingleChoice,
    SingleChoiceElement,
    String,
)
from cmk.rulesets.v1.rule_specs import NotificationParameters, Topic


def _form() -> Dictionary:
    return Dictionary(
        title=Title("Splunk HTTP Event Collector"),
        help_text=Help(
            "Send Checkmk notifications as CIM Alerts JSON to Splunk HEC. "
            "Store the HEC token in the Checkmk password store when possible."
        ),
        elements={
            "hec_url": DictElement(
                required=True,
                parameter_form=String(
                    title=Title("HEC URL"),
                    help_text=Help(
                        "Full collector URL, for example "
                        "https://splunk.example.com:8088/services/collector/event"
                    ),
                ),
            ),
            "hec_token": DictElement(
                required=True,
                parameter_form=String(
                    title=Title("HEC token"),
                    help_text=Help(
                        "Raw token, or a password-store reference of the form "
                        "'store <password_id>'."
                    ),
                ),
            ),
            "index": DictElement(
                required=False,
                parameter_form=String(
                    title=Title("Splunk index"),
                    prefill=DefaultValue("checkmk"),
                ),
            ),
            "sourcetype": DictElement(
                required=False,
                parameter_form=String(
                    title=Title("Sourcetype"),
                    prefill=DefaultValue("checkmk:alert"),
                ),
            ),
            "verify_tls": DictElement(
                required=False,
                parameter_form=SingleChoice(
                    title=Title("Verify TLS certificate"),
                    prefill=DefaultValue("yes"),
                    elements=[
                        SingleChoiceElement(name="yes", title=Title("Yes")),
                        SingleChoiceElement(name="no", title=Title("No")),
                    ],
                ),
            ),
        },
    )


rule_spec_splunk_hec = NotificationParameters(
    name="splunk_hec",
    title=Title("Splunk HTTP Event Collector"),
    topic=Topic.NOTIFICATIONS,
    parameter_form=_form,
)
