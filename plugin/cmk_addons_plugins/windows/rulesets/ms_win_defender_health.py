#!/usr/bin/env python3
# -*- coding: utf-8; py-indent-offset: 4; max-line-length: 100 -*-

# Copyright (C) 2025  Christopher Pommer <cp.software@outlook.de>

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.


####################################################################################################
# Checkmk ruleset to set the different values for the Windows Defender health check.
# This ruleset is part of the Microsoft Windows Defender plugin (ms_win_defender).


from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    CascadingSingleChoice,
    CascadingSingleChoiceElement,
    DefaultValue,
    DictElement,
    Dictionary,
    FixedValue,
    Integer,
    LevelDirection,
    MultipleChoice,
    MultipleChoiceElement,
    ServiceState,
    SimpleLevels,
)
from cmk.rulesets.v1.form_specs.validators import NumberInRange
from cmk.rulesets.v1.rule_specs import (
    CheckParameters,
    HostCondition,
    Topic,
)


def _parameter_form_ms_win_defender_health() -> Dictionary:
    return Dictionary(
        title=Title("Check Parameters"),
        help_text=Help(
            "Check parameters for the Windows Defender health check. To use this service, you need "
            "to deploy the <b>Microsoft Windows Defender</b> agent plugin."
        ),
        elements={
            "running_mode": DictElement(
                parameter_form=CascadingSingleChoice(
                    title=Title("Expected Running Mode"),
                    help_text=Help(
                        "Define the expected running mode for the Windows Defender.<br>"
                        "If the actual mode differs from the expected mode, then the service "
                        "will be <tt>CRIT</tt>.<br><br>"
                        "<b>Active Mode</b>: Full protection with real-time scanning<br>"
                        "<b>Passive Mode</b>: Limited functionality alongside third-party AV<br>"
                        "<b>EDR Block Mode</b>: Endpoint Detection and Response blocking<br>"
                        "<b>SxS Passive Mode</b>: Side-by-side passive operation<br>"
                        "<b>Disabled</b>: Windows Defender is turned off"
                    ),
                    elements=[
                        CascadingSingleChoiceElement(
                            name="active_mode",
                            title=Title("Normal (Active Mode)"),
                            parameter_form=FixedValue(value=None),
                        ),
                        CascadingSingleChoiceElement(
                            name="disabled",
                            title=Title("Not Running (Disabled)"),
                            parameter_form=FixedValue(value=None),
                        ),
                        CascadingSingleChoiceElement(
                            name="edr_block_mode",
                            title=Title("EDR Block Mode"),
                            parameter_form=FixedValue(value=None),
                        ),
                        CascadingSingleChoiceElement(
                            name="passive_mode",
                            title=Title("Passive Mode"),
                            parameter_form=FixedValue(value=None),
                        ),
                        CascadingSingleChoiceElement(
                            name="sxs_passive_mode",
                            title=Title("SxS Passive Mode"),
                            parameter_form=FixedValue(value=None),
                        ),
                    ],
                    prefill=DefaultValue("active_mode"),
                ),
                required=True,
            ),
            "expected_enabled_features": DictElement(
                parameter_form=MultipleChoice(
                    title=Title("Expected Enabled Features"),
                    help_text=Help(
                        "Select which Windows Defender features must be enabled.<br>"
                        "If any of the selected features are disabled on the system, then the "
                        "service will be <tt>CRIT</tt>.<br>"
                        "The default selection includes all protection features."
                    ),
                    elements=[
                        MultipleChoiceElement(
                            name="am_service",
                            title=Title("Antimalware Service"),
                        ),
                        MultipleChoiceElement(
                            name="antivirus",
                            title=Title("Antivirus Engine"),
                        ),
                        MultipleChoiceElement(
                            name="antispyware",
                            title=Title("Antispyware Engine"),
                        ),
                        MultipleChoiceElement(
                            name="behavior_monitor",
                            title=Title("Behavior Monitoring"),
                        ),
                        MultipleChoiceElement(
                            name="ioav_protection",
                            title=Title("IOAV Protection"),
                        ),
                        MultipleChoiceElement(
                            name="network_protection",
                            title=Title("Network Protection"),
                        ),
                        MultipleChoiceElement(
                            name="on_access_protection",
                            title=Title("On-Access Protection"),
                        ),
                        MultipleChoiceElement(
                            name="real_time_protection",
                            title=Title("Real-time Protection"),
                        ),
                        MultipleChoiceElement(
                            name="tamper_protection",
                            title=Title("Tamper Protection"),
                        ),
                    ],
                    prefill=DefaultValue(
                        value=(
                            [
                                "am_service",
                                "antispyware",
                                "antivirus",
                                "behavior_monitor",
                                "ioav_protection",
                                "network_protection",
                                "on_access_protection",
                                "real_time_protection",
                                "tamper_protection",
                            ]
                        )
                    ),
                ),
            ),
            "max_quick_scan_age": DictElement(
                parameter_form=SimpleLevels[int](
                    title=Title("Max. Quick Scan Age"),
                    help_text=Help(
                        "Specify the upper thresholds for the maximum age of the last quick scan."
                        "<br>The default values are 3 days (WARN) and 6 days (CRIT).<br>"
                        'To ignore the quick scan age, select "No levels".'
                    ),
                    form_spec_template=Integer(
                        custom_validate=(NumberInRange(min_value=1),),
                        unit_symbol="days",
                    ),
                    level_direction=LevelDirection.UPPER,
                    prefill_fixed_levels=DefaultValue(value=(3, 6)),
                ),
            ),
            "max_full_scan_age": DictElement(
                parameter_form=SimpleLevels[int](
                    title=Title("Max. Full Scan Age"),
                    help_text=Help(
                        "Specify the upper thresholds for the maximum age of the last full scan. "
                        "<br>There are no default thresholds.<br>"
                        'To ignore the full scan age, select "No levels".'
                    ),
                    form_spec_template=Integer(
                        custom_validate=(NumberInRange(min_value=1),),
                        unit_symbol="days",
                    ),
                    level_direction=LevelDirection.UPPER,
                    prefill_fixed_levels=DefaultValue(value=(0.0, 0.0)),
                ),
            ),
            "outdated_signatures_state": DictElement(
                parameter_form=ServiceState(
                    title=Title("Outdated Signatures State"),
                    help_text=Help(
                        "Set the service state when Windows Defender signatures are outdated.<br>"
                        "By default, Windows Defender considers signatures outdated after 14 days, "
                        "but this can be configured via Group Policy, SCCM, etc.<br>"
                        "The default severity level is <tt>WARN</tt>."
                    ),
                    prefill=DefaultValue(1),
                ),
            ),
        },
    )


rule_spec_ms_win_defender_health = CheckParameters(
    name="ms_win_defender_health",
    title=Title("Microsoft Windows Defender Health"),
    parameter_form=_parameter_form_ms_win_defender_health,
    topic=Topic.OPERATING_SYSTEM,
    condition=HostCondition(),
)
