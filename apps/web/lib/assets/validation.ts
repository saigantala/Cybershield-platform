import { CreateAssetInput, DeviceType, RiskLevel, AssetStatus } from "@/types/asset";

export interface ValidationError {
  field: string;
  message: string;
}

export function isValidIPv4(ip: string): boolean {
  if (!ip) return false;
  const parts = ip.trim().split(".");
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    if (!/^\d+$/.test(part)) return false;
    const num = parseInt(part, 10);
    return num >= 0 && num <= 255 && (part === "0" || !part.startsWith("0"));
  });
}

export function isValidMAC(mac: string | undefined | null): boolean {
  if (!mac || mac.trim() === "") return true; // Optional field
  const regex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
  return regex.test(mac.trim());
}

export function validateAssetInput(input: Partial<CreateAssetInput>): {
  isValid: boolean;
  errors: Record<string, string>;
} {
  const errors: Record<string, string> = {};

  if (!input.name || input.name.trim().length === 0) {
    errors.name = "Device name is required";
  } else if (input.name.trim().length > 100) {
    errors.name = "Device name cannot exceed 100 characters";
  }

  if (!input.ip_address || input.ip_address.trim().length === 0) {
    errors.ip_address = "IP address is required";
  } else if (!isValidIPv4(input.ip_address)) {
    errors.ip_address = "Invalid IPv4 address format (e.g. 192.168.1.50)";
  }

  if (input.mac_address && !isValidMAC(input.mac_address)) {
    errors.mac_address = "Invalid MAC address format (e.g. 52:54:00:8F:90:A1 or 52-54-00-8F-90-A1)";
  }

  const validDeviceTypes: DeviceType[] = [
    "Laptop",
    "Desktop",
    "Server",
    "Router",
    "Mobile",
    "IoT",
    "Other",
  ];
  if (!input.device_type || !validDeviceTypes.includes(input.device_type)) {
    errors.device_type = "Valid device type is required";
  }

  const validRiskLevels: RiskLevel[] = [
    "Critical",
    "High",
    "Medium",
    "Low",
    "Unassessed",
  ];
  if (!input.risk_level || !validRiskLevels.includes(input.risk_level)) {
    errors.risk_level = "Valid risk level is required";
  }

  const validStatuses: AssetStatus[] = ["Active", "Inactive", "Unknown"];
  if (!input.status || !validStatuses.includes(input.status)) {
    errors.status = "Valid status is required";
  }

  return {
    isValid: Object.keys(errors).length === 0,
    errors,
  };
}
