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
# Checkmk check plugin for monitoring the Windows Defender state on a Windows host.
# This is part of the Microsoft Windows Defender plugin (ms_win_defender), which uses data generated
# from the Windows defender script (ms_win_defender.ps1).

# Example data from agent plugin:
# <<<ms_win_defender_health:sep(124)>>>
# AMRunningMode|Normal
# AMServiceEnabled|True
# AntispywareEnabled|True
# AntispywareSignatureAge|0
# AntivirusEnabled|True
# AntivirusSignatureAge|0
# BehaviorMonitorEnabled|True
# DefenderSignaturesOutOfDate|False
# FullScanAge|4294967295
# IoavProtectionEnabled|True
# NISEnabled|True
# OnAccessProtectionEnabled|True
# QuickScanAge|0
# RealTimeProtectionEnabled|True

from collections.abc import Mapping
from typing import Any

from cmk.agent_based.v2 import (
    AgentSection,
    check_levels,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Result,
    Service,
    State,
    StringTable,
)


Section = Mapping[str, str]


def parse_ms_win_defender_health(string_table: StringTable) -> Section:
    parsed = {}
    for line in string_table:
        if len(line) >= 2:
            key = line[0].strip()
            value = line[1].strip()
            parsed[key] = value

    return parsed


def discover_ms_win_defender_health(section: Section) -> DiscoveryResult:
    yield Service()


def check_ms_win_defender_health(params: Mapping[str, Any], section: Section) -> CheckResult:
    if not section:
        yield Result(state=State.UNKNOWN, summary="No data available")
        return

    RUNNING_MODE_MAPPING = {
        "active_mode": "Normal",
        "disabled": "Not running",
        "edr_block_mode": "EDR Block Mode",
        "passive_mode": "Passive Mode",
        "sxs_passive_mode": "SxS Passive Mode",
    }

    am_running_mode = section["AMRunningMode"]
    am_running_mode_lower = am_running_mode.lower()
    am_running_mode_param = params["running_mode"][0]

    am_running_mode_state = State.OK
    am_running_mode_summary = f"Mode: {am_running_mode}"

    if am_running_mode_param is not None:
        expected_section_value = RUNNING_MODE_MAPPING.get(am_running_mode_param)
        if expected_section_value and am_running_mode_lower != expected_section_value.lower():
            am_running_mode_state = State.CRIT
            am_running_mode_summary += f" (Expected: {expected_section_value})"

    yield Result(state=am_running_mode_state, summary=am_running_mode_summary)

    expected_enabled_features = params["expected_enabled_features"]

    if expected_enabled_features:
        FEATURE_ATTRIBUTE_MAPPING = {
            "AMServiceEnabled": "Antimalware Service",
            "AntispywareEnabled": "Antispyware Engine",
            "AntivirusEnabled": "Antivirus Engine",
            "BehaviorMonitorEnabled": "Behavior Monitoring",
            "IoavProtectionEnabled": "IOAV Protection",
            "OnAccessProtectionEnabled": "On-Access Protection",
            "RealTimeProtectionEnabled": "Real-time Protection",
            "NISEnabled": "Network Protection",
            "IsTamperProtected": "Tamper Protection",
        }

        FEATURE_PARAM_MAPPING = {
            "am_service": "AMServiceEnabled",
            "antispyware": "AntispywareEnabled",
            "antivirus": "AntivirusEnabled",
            "behavior_monitor": "BehaviorMonitorEnabled",
            "ioav_protection": "IoavProtectionEnabled",
            "network_protection": "NISEnabled",
            "on_access_protection": "OnAccessProtectionEnabled",
            "real_time_protection": "RealTimeProtectionEnabled",
            "tamper_protection": "IsTamperProtected",
        }

        disabled_features = []
        enabled_features_count = 0

        for feature in expected_enabled_features:
            feature_attribute = FEATURE_PARAM_MAPPING[feature]
            if section.get(feature_attribute) == "True":
                enabled_features_count += 1
            else:
                disabled_features.append(FEATURE_ATTRIBUTE_MAPPING[feature_attribute])

        yield Result(
            state=State.OK,
            summary=f"Features: {enabled_features_count}/{len(expected_enabled_features)} active",
        )

        if disabled_features:
            yield Result(
                state=State.CRIT,
                summary=f"Disabled: {', '.join(disabled_features)}",
            )

    quick_scan_age = section["QuickScanAge"]
    yield from check_levels(
        int(quick_scan_age),
        levels_upper=params.get("max_quick_scan_age"),
        label="Quick scan age",
        render_func=lambda x: f"{x} days" if x != 4294967295 else "Never",
        notice_only=True,
    )

    full_scan_age = section["FullScanAge"]
    yield from check_levels(
        int(full_scan_age),
        levels_upper=params.get("max_full_scan_age"),
        label="Full scan age",
        render_func=lambda x: f"{x} days" if x != 4294967295 else "Never",
        notice_only=True,
    )

    if section["DefenderSignaturesOutOfDate"] == "True":
        yield Result(
            state=State.WARN,
            summary="Signatures out of date",
        )


agent_section_ms_win_defender_health = AgentSection(
    name="ms_win_defender_health",
    parse_function=parse_ms_win_defender_health,
)


check_plugin_ms_win_defender_health = CheckPlugin(
    name="ms_win_defender_health",
    service_name="Windows Defender health",
    discovery_function=discover_ms_win_defender_health,
    check_function=check_ms_win_defender_health,
    check_ruleset_name="ms_win_defender_health",
    check_default_parameters={
        "running_mode": ("active_mode", None),
        "expected_enabled_features": [
            "am_service",
            "antispyware",
            "antivirus",
            "behavior_monitor",
            "ioav_protection",
            "network_protection",
            "on_access_protection",
            "real_time_protection",
            "tamper_protection",
        ],
        "max_quick_scan_age": ("fixed", (3, 6)),
    },
)
