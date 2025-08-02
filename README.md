# Checkmk Plugin: Microsoft Windows Defender

The **Microsoft Windows Defender** agent plugin is an extension for the monitoring software **Checkmk**.  
It can be integrated into Checkmk 2.3 or newer.

You can download the extension package as an `.mkp` file from the [releases](../../releases) in this repository and upload it directly to your Checkmk site.  
See the Checkmk [documentation](https://docs.checkmk.com/latest/en/mkps.html) for details.

## Plugin Information

The plugin provides monitoring of Windows Defender health, including running mode, enabled features, scan age, and outdated signatures.

See [Check Details](#check-details) for more information.

## Check Details

### Windows Defender Health

#### Description

This check monitors the health of the Windows Defender.
It provides information about
- Expected Running Mode
- Expected Enabled Features
- Quick Scan Age in Days
- Full Scan Age in Days
- Signatures out of Date

#### Checkmk Service Examples

<img width="712" height="61" alt="grafik" src="https://github.com/user-attachments/assets/ffc855f7-e123-465f-a930-aa1452ee9749" />
<img width="1055" height="61" alt="grafik" src="https://github.com/user-attachments/assets/b06f5bda-5cc5-4a1b-bb78-9142fec33009" />
<img width="1038" height="66" alt="grafik" src="https://github.com/user-attachments/assets/a55bbefb-d478-4e88-9ae1-535ebd614abe" />

#### Checkmk Parameters

1. **Expected Running Mode**: Define the expected running mode for the Windows Defender. If the actual mode differs from the expected mode, then the service will be CRIT.
2. **Expected Enabled Features**: Select which Windows Defender features must be enabled. If any of the selected features are disabled on the system, then the service will be CRIT. The default selection includes all protection features.
3. **Max. Quick Scan Age**: Specify the upper thresholds for the maximum age of the last quick scan. The default values are 3 days (WARN) and 6 days (CRIT). To ignore the quick scan age, select "No levels".
4. **Max. Full Scan Age**: Specify the upper thresholds for the maximum age of the last full scan. There are no default thresholds. To ignore the full scan age, select "No levels".
5. **Outdated Signatures State**: Set the service state when Windows Defender signatures are outdated. By default, Windows Defender considers signatures outdated after 14 days, but this can be configured via Group Policy, SCCM, etc. The default severity level is WARN.

