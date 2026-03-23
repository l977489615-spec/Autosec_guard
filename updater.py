import os

mappings = {
    "network/66_SOMEIP_Service_Discovery.py": "network/19_SOMEIP_Service_Discovery.py",
    "canbus/67_UDS_ECU_Reset_Unauth.py": "canbus/29_UDS_ECU_Reset_Unauth.py",
    "canbus/27_OBD_VIN_Spoof.py": "canbus/28_OBD_VIN_Spoof.py",
    "canbus/26_UDS_RoutineControl.py": "canbus/27_UDS_RoutineControl.py",
    "canbus/25_UDS_ReadMemory.py": "canbus/26_UDS_ReadMemory.py",
    "canbus/24_UDS_Security_Access_Brute.py": "canbus/25_UDS_Security_Access_Brute.py",
    "canbus/23_UDS_DiagSession_Bypass.py": "canbus/24_UDS_DiagSession_Bypass.py",
    "canbus/22_CAN_Replay_Attack.py": "canbus/23_CAN_Replay_Attack.py",
    "canbus/21_CAN_DoS_Flood.py": "canbus/22_CAN_DoS_Flood.py",
    "canbus/20_CAN_Message_Injection.py": "canbus/21_CAN_Message_Injection.py",
    "canbus/19_CAN_Bus_Sniff.py": "canbus/20_CAN_Bus_Sniff.py",
    "wireless/65_WiFi_SSID_Clone_AutoConnect.py": "wireless/47_WiFi_SSID_Clone_AutoConnect.py",
    "wireless/63_BT_CVE_2020_0022_DoS.py": "wireless/46_BT_CVE_2020_0022_DoS.py",
    "wireless/43_BleedingTooth_L2CAP.py": "wireless/45_BleedingTooth_L2CAP.py",
    "wireless/42_BlueBorne_BNEP_Overflow.py": "wireless/44_BlueBorne_BNEP_Overflow.py",
    "wireless/41_BT_Keystroke_Injection.py": "wireless/43_BT_Keystroke_Injection.py",
    "wireless/40_BT_HFP_UAF.py": "wireless/42_BT_HFP_UAF.py",
    "wireless/39_BT_PerfektBlue_RFCOMM.py": "wireless/41_BT_PerfektBlue_RFCOMM.py",
    "wireless/38_BT_PerfektBlue_L2CAP.py": "wireless/40_BT_PerfektBlue_L2CAP.py",
    "wireless/37_BT_BLUFFS_Key_Downgrade.py": "wireless/39_BT_BLUFFS_Key_Downgrade.py",
    "wireless/36_BT_HFP_AT_Overflow.py": "wireless/38_BT_HFP_AT_Overflow.py",
    "wireless/35_WiFi_Unauth_Vehicle_Ctrl.py": "wireless/37_WiFi_Unauth_Vehicle_Ctrl.py",
    "wireless/34_Broadcom_WME_Overflow.py": "wireless/36_Broadcom_WME_Overflow.py",
    "wireless/33_ConnMan_DHCP_Overflow.py": "wireless/35_ConnMan_DHCP_Overflow.py",
    "wireless/32_WiFi_TI_WL18xx_Overflow.py": "wireless/34_WiFi_TI_WL18xx_Overflow.py",
    "wireless/31_WiFi_KRACK.py": "wireless/33_WiFi_KRACK.py",
    "wireless/30_WiFi_Evil_Twin.py": "wireless/32_WiFi_Evil_Twin.py",
    "wireless/29_WiFi_Deauth.py": "wireless/31_WiFi_Deauth.py",
    "wireless/28_QNX_Qnet_File_Read.py": "wireless/30_QNX_Qnet_File_Read.py",
    "application/64_UPnP_AVTransport_Media_Inject.py": "application/59_UPnP_AVTransport_Media_Inject.py",
    "application/62_RTSP_CarPlay_DoS.py": "application/58_RTSP_CarPlay_DoS.py",
    "application/53_Wireless_Dongle_Auth_Bypass.py": "application/57_Wireless_Dongle_Auth_Bypass.py",
    "application/52_IVI_DevMode_Bypass.py": "application/56_IVI_DevMode_Bypass.py",
    "application/51_USB_Path_Injection.py": "application/55_USB_Path_Injection.py",
    "application/50_Filename_Command_Injection.py": "application/54_Filename_Command_Injection.py",
    "application/49_WebView_File_Exfil.py": "application/53_WebView_File_Exfil.py",
    "application/48_HiQnet_Heap_Overflow_UDP.py": "application/52_HiQnet_Heap_Overflow_UDP.py",
    "application/47_HiQnet_Stack_Overflow_TCP.py": "application/51_HiQnet_Stack_Overflow_TCP.py",
    "application/46_CarPlay_Stack_Overflow.py": "application/50_CarPlay_Stack_Overflow.py",
    "application/45_IVI_USB_SQLi.py": "application/49_IVI_USB_SQLi.py",
    "application/44_AirPlay_AirBorne_UAF.py": "application/48_AirPlay_AirBorne_UAF.py",
    "advanced/61_USB_Unsigned_Update.py": "advanced/67_USB_Unsigned_Update.py",
    "advanced/60_QNX_Unsigned_Firmware.py": "advanced/66_QNX_Unsigned_Firmware.py",
    "advanced/59_FW_Update_TOCTOU.py": "advanced/65_FW_Update_TOCTOU.py",
    "advanced/58_V2X_BSM_Injection.py": "advanced/64_V2X_BSM_Injection.py",
    "advanced/57_TPMS_Signal_Spoofing.py": "advanced/63_TPMS_Signal_Spoofing.py",
    "advanced/56_GPS_Spoofing.py": "advanced/62_GPS_Spoofing.py",
    "advanced/55_RF_Keyfob_Replay.py": "advanced/61_RF_Keyfob_Replay.py",
    "advanced/54_OTA_MITM_Interception.py": "advanced/60_OTA_MITM_Interception.py"
}

file_path = "client/constants.ts"
with open(file_path, "r") as f:
    content = f.read()

for old, new in mappings.items():
    content = content.replace(old, new)

with open(file_path, "w") as f:
    f.write(content)

print(f"Updated {file_path}")
