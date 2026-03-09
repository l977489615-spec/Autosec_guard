import os
import shutil

POCS_DIR = "/Users/queen/Desktop/ICV_POC_research/autosec-guard---icv-vulnerability-scanner/Pocs"
CONSTANTS_FILE = "/Users/queen/Desktop/ICV_POC_research/autosec-guard---icv-vulnerability-scanner/constants.ts"

# Original filename to New desired filename mapping
MAPPING = {
    # Phase 1: Recon (8)
    "32_ICMP_Host_Discovery.py": "01_ICMP_Host_Discovery.py",
    "33_TCP_Port_Scan.py": "02_TCP_Port_Scan.py",
    "34_mDNS_Service_Discovery.py": "03_mDNS_Service_Discovery.py",
    "35_UPnP_SSDP_Discovery.py": "04_UPnP_SSDP_Discovery.py",
    "36_SNMP_Info_Leak.py": "05_SNMP_Info_Leak.py",
    "49_BT_SDP_Enum.py": "06_BT_SDP_Enum.py",
    "58_TBOX_Port_Scan.py": "07_TBOX_Port_Scan.py",
    "30_HTTP_Service_Enum.py": "08_HTTP_Service_Enum.py",

    # Phase 2: Network Services (10)
    "27_ADB_Debug_Port.py": "09_ADB_Debug_Port.py",
    "28_SSH_Weak_Creds.py": "10_SSH_Weak_Creds.py",
    "13_ToyotaHarmanSSHExploit.py": "11_SSH_Hardcoded_Creds.py",
    "29_Telnet_Service.py": "12_Telnet_Service.py",
    "31_FTP_Anonymous.py": "13_FTP_Anonymous.py",
    "55_MQTT_Unauth.py": "14_MQTT_Unauth.py",
    "9_JeepDBusPlugin.py": "15_DBus_Anon_Auth.py",
    "23_RTSPLogLeakPlugin.py": "16_RTSP_Log_Leak.py",
    "24_DLNAAVTransportPlugin.py": "17_DLNA_AVTransport_Unauth.py",
    "14_PioneerHTTPSExploit.py": "18_HTTPS_No_Cert_Pin.py",

    # Phase 3: Protocol Exploits (10)
    "37_CAN_Bus_Sniff.py": "19_CAN_Bus_Sniff.py",
    "38_CAN_Message_Injection.py": "20_CAN_Message_Injection.py",
    "39_CAN_DoS_Flood.py": "21_CAN_DoS_Flood.py",
    "40_CAN_Replay_Attack.py": "22_CAN_Replay_Attack.py",
    "41_UDS_DiagSession_Bypass.py": "23_UDS_DiagSession_Bypass.py",
    "0_BaseTest.py": "24_UDS_Security_Access_Brute.py", # Reused BaseTest for this since it had UDS seed-key originally
    "42_UDS_ReadMemory.py": "25_UDS_ReadMemory.py",
    "43_UDS_RoutineControl.py": "26_UDS_RoutineControl.py",
    "44_OBD_VIN_Spoof.py": "27_OBD_VIN_Spoof.py",
    "8_QNXQnetPlugin.py": "28_QNX_Qnet_File_Read.py",

    # Phase 4: Wireless (16)
    "50_WiFi_Deauth.py": "29_WiFi_Deauth.py",
    "51_WiFi_Evil_Twin.py": "30_WiFi_Evil_Twin.py",
    "52_WiFi_KRACK.py": "31_WiFi_KRACK.py",
    "2_FordSyncWifiPlugin.py": "32_WiFi_TI_WL18xx_Overflow.py",
    "11_TeslaConnManExploit.py": "33_ConnMan_DHCP_Overflow.py",
    "22_BroadpwnExploit.py": "34_Broadcom_WME_Overflow.py",
    "20_MitsubishiWiFiExploit.py": "35_WiFi_Unauth_Vehicle_Ctrl.py",
    "5_NissanBlueOverflowPlugin.py": "36_BT_HFP_AT_Overflow.py",
    "45_BT_BLUFFS.py": "37_BT_BLUFFS_Key_Downgrade.py",
    "46_BT_PerfektBlue_L2CAP.py": "38_BT_PerfektBlue_L2CAP.py",
    "47_BT_PerfektBlue_RFCOMM.py": "39_BT_PerfektBlue_RFCOMM.py",
    "48_BT_HFP_UAF.py": "40_BT_HFP_UAF.py",
    "25_BluetoothKeyboardSpoofPlugin.py": "41_BT_Keystroke_Injection.py",
    "7_BlueBornePlugin.py": "42_BlueBorne_BNEP_Overflow.py",
    "19_BleedingToothExploit.py": "43_BleedingTooth_L2CAP.py",
    "26_AirBorneVerifyPlugin.py": "44_AirPlay_AirBorne_UAF.py",

    # Phase 5: Application & Local (10)
    "1_MazdaSQLiPlugin.py": "45_IVI_USB_SQLi.py",
    "4_AlpineCarPlayPlugin.py": "46_CarPlay_Stack_Overflow.py",
    "3_MercedesHiQnetPlugin.py": "47_HiQnet_Stack_Overflow_TCP.py",
    "17_MercedesHiQnetExploit.py": "48_HiQnet_Heap_Overflow_UDP.py",
    "21_HondaWebViewExploit.py": "49_WebView_File_Exfil.py",
    "15_AlpineCommandInjectionPoC.py": "50_Filename_Command_Injection.py",
    "16_MazdaCMUExploit.py": "51_USB_Path_Injection.py",
    "56_IVI_DevMode_Bypass.py": "52_IVI_DevMode_Bypass.py",
    "57_CarlinKit_Auth_Bypass.py": "53_Wireless_Dongle_Auth_Bypass.py",
    "59_OTA_MITM.py": "54_OTA_MITM_Interception.py",

    # Phase 6: Advanced/Hardware (6)
    "10_HondaReplayPlugin.py": "55_RF_Keyfob_Replay.py",
    # GPS doesn't have a script, but we can create a dummy one or use None.
    "53_TPMS_Spoof.py": "57_TPMS_Signal_Spoofing.py",
    "54_V2X_BSM_Spoof.py": "58_V2X_BSM_Injection.py",
    "6_TeslaGatewayRacePlugin.py": "59_FW_Update_TOCTOU.py",
    "18_SubaruUpdateExploit.py": "60_QNX_Unsigned_Firmware.py",
    "12_KiaHyundaiAppUpgradeExploit.py": "61_USB_Unsigned_Update.py", # Need to fit this in
}

# Add a dummy for GPS to make it 60 actual script files if needed, but since 12_KiaHyundai was left out, let's use it
# The original 60 included 12_KiaHyundai, we have 61 now?
# MAPPING length is 59 files mapped. Since one in constants.ts was missing pocFile (GPS Spoofing).

# Rename files in directory
for old_file, new_file in MAPPING.items():
    old_path = os.path.join(POCS_DIR, old_file)
    new_path = os.path.join(POCS_DIR, new_file)
    if os.path.exists(old_path):
        os.rename(old_path, new_path)
        print(f"Renamed: {old_file} -> {new_file}")

# Special handling for "0_BaseTest.py" becoming UDS Security Access
with open(os.path.join(POCS_DIR, "24_UDS_Security_Access_Brute.py"), 'r', encoding='utf-8') as f:
    content = f.read()
    content = content.replace("0_BaseTest.py", "24_UDS_Security_Access_Brute.py")
with open(os.path.join(POCS_DIR, "24_UDS_Security_Access_Brute.py"), 'w', encoding='utf-8') as f:
    f.write(content)

# Update constants.ts
with open(CONSTANTS_FILE, 'r', encoding='utf-8') as f:
    constants = f.read()

for old_file, new_file in MAPPING.items():
    if old_file in constants:
        constants = constants.replace(old_file, new_file)

with open(CONSTANTS_FILE, 'w', encoding='utf-8') as f:
    f.write(constants)

print("Renaming complete.")
