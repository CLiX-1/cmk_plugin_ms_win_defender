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
# Checkmk agent script for monitoring the Windows Defender health.
# This script is part of the Microsoft Windows Defender plugin (ms_win_defender).


try {
    $DefenderStatus = Get-MpComputerStatus
}
catch {
    exit
}

$DefenderStatus = $DefenderStatus | Select-Object -Property AMRunningMode,
AMServiceEnabled,
AntispywareEnabled,
AntispywareSignatureAge,
AntivirusEnabled,
AntivirusSignatureAge,
BehaviorMonitorEnabled,
DefenderSignaturesOutOfDate,
FullScanAge,
IsTamperProtected,
IoavProtectionEnabled,
NISEnabled,
OnAccessProtectionEnabled,
QuickScanAge,
RealTimeProtectionEnabled


Write-Host "<<<ms_win_defender_health:sep(124)>>>"

foreach ($Property in $DefenderStatus.PSObject.Properties) {
    Write-Output "$($Property.Name)|$($Property.Value)"
}
