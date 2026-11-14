# Set the Windows default playback/recording device by name (all roles).
# Usage: set_audio_default.ps1 -Playback "Realtek" -Recording "Realtek"
param([string]$Playback, [string]$Recording, [switch]$List)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;

[Guid("f8679f50-850a-41cf-9c72-430f290290c8"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IPolicyConfig {
    int GetMixFormat(); int GetDeviceFormat(); int ResetDeviceFormat(); int SetDeviceFormat();
    int GetProcessingPeriod(); int SetProcessingPeriod(); int GetShareMode(); int SetShareMode();
    int GetPropertyValue(); int SetPropertyValue();
    int SetDefaultEndpoint([MarshalAs(UnmanagedType.LPWStr)] string id, int role);
    int SetEndpointVisibility();
}
[ComImport, Guid("870af99c-171d-4f9e-af0d-e63df40c2bc9")] class PolicyConfigClient {}

[Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IMMDeviceEnumerator {
    int EnumAudioEndpoints(int flow, int mask, out IMMDeviceCollection c);
}
[Guid("0BD7A1BE-7A1A-44DB-8397-CC5392387B5E"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IMMDeviceCollection { int GetCount(out int n); int Item(int i, out IMMDevice d); }
[Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IMMDevice {
    int Activate(); int OpenPropertyStore(int access, out IPropertyStore p);
    int GetId([MarshalAs(UnmanagedType.LPWStr)] out string id);
}
[Guid("886d8eeb-8cf2-4446-8d02-cdba1dbdcf99"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IPropertyStore { int GetCount(); int GetAt(); int GetValue(ref PROPERTYKEY k, out PROPVARIANT v); }
[StructLayout(LayoutKind.Sequential)] struct PROPERTYKEY { public Guid fmtid; public int pid; }
[StructLayout(LayoutKind.Explicit)] struct PROPVARIANT { [FieldOffset(0)] public short vt; [FieldOffset(8)] public IntPtr p; }
[ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")] class MMDeviceEnumerator {}

public static class AudioDefaults {
    // flow: 0 = playback, 1 = recording. Returns "id|name" lines for active devices.
    public static List<string> List(int flow) {
        var r = new List<string>();
        var e = (IMMDeviceEnumerator)new MMDeviceEnumerator();
        IMMDeviceCollection c; e.EnumAudioEndpoints(flow, 1, out c);
        int n; c.GetCount(out n);
        var key = new PROPERTYKEY { fmtid = new Guid("a45c254e-df1c-4efd-8020-67d146a850e0"), pid = 14 };
        for (int i = 0; i < n; i++) {
            IMMDevice d; c.Item(i, out d);
            string id; d.GetId(out id);
            IPropertyStore s; d.OpenPropertyStore(0, out s);
            PROPVARIANT v; s.GetValue(ref key, out v);
            r.Add(id + "|" + Marshal.PtrToStringUni(v.p));
        }
        return r;
    }
    public static void SetDefault(string id) {
        var p = (IPolicyConfig)new PolicyConfigClient();
        for (int role = 0; role < 3; role++) p.SetDefaultEndpoint(id, role);
    }
}
"@

function Set-ByName([int]$flow, [string]$match) {
    $hit = [AudioDefaults]::List($flow) | Where-Object { ($_ -split '\|', 2)[1] -match $match } | Select-Object -First 1
    if (-not $hit) { throw "No active device matching '$match'" }
    $id, $name = $hit -split '\|', 2
    [AudioDefaults]::SetDefault($id)
    "default $(@('playback','recording')[$flow]): $name"
}

if ($List) { [AudioDefaults]::List(0) | ForEach-Object { "out: " + ($_ -split '\|',2)[1] }; [AudioDefaults]::List(1) | ForEach-Object { "in:  " + ($_ -split '\|',2)[1] } }
if ($Playback) { Set-ByName 0 $Playback }
if ($Recording) { Set-ByName 1 $Recording }
