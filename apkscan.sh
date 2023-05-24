#!/bin/bash

# Define colors
GREEN='\033[1;32m'
RED='\033[1;31m'
NC='\033[0m' # No Color

#Check Dependencies
command -v adb >/dev/null 2>&1 || { echo -e >&2 "${RED}adb is not installed. Please install it.${NC}"; exit 1; }
command -v jq >/dev/null 2>&1 || { echo -e >&2 "${RED}jq is not installed. Please install it.${NC}"; exit 1; }

# Check if any device is connected
device=$(adb devices | sed '1d' | awk '{print $1}')

if [ -z "$device" ]; then
  echo -e "${RED}No device is connected via adb.${NC}"
  exit 1
else
  echo -e "${GREEN}Device connected via adb: $device${NC}"
  echo
fi

# Output directory to save the extracted APKs
output_dir="$HOME/extracted_packages"
mkdir -p "$output_dir"

# Get a list of installed packages from the device
packages=$(adb shell pm list packages -3 | sed -e 's/^.*://')

# Count the total number of packages
total_packages=$(echo "$packages" | wc -l)
extracted_count=0
malicious_count=0
safe_count=0


# Iterate over each package and extract the APK
for package in $packages; do
  # Extract the APK using ADB
  echo -ne "Extracting ${GREEN}$package...${NC}\n"
  apk_path=$(adb shell "pm path $package" | grep base |  awk -F':' '{print $2}' | tr -d '\r')

  if [ -n "$apk_path" ]; then
    extracted_count=$((extracted_count + 1))
    echo -ne "Extracting APKs: ${GREEN}$extracted_count${NC} / $total_packages\r"

    adb pull "$apk_path" "$output_dir/$package.apk" >> /dev/null

    # Check if the APK was successfully extracted
    if [ $? -eq 0 ]; then
      echo -e "APK extracted: ${GREEN}$package${NC}\n"
    else
      echo -e "Failed to extract APK: ${RED}$package${NC}"
    fi
  fi
done

echo
echo -e "${GREEN}APK extraction completed. $extracted_count APKs extracted.${NC}"

# Verify the number of APKs in the output directory
extracted_packages=$(ls -1 "$output_dir"/*.apk 2>/dev/null | wc -l)

if [ "$extracted_count" -eq "$extracted_packages" ]; then
  echo -e "${GREEN}Number of extracted APKs matches the count: $extracted_packages${NC}"
else
  echo -e "${RED}Number of extracted APKs ($extracted_packages) does not match the count ($extracted_count)${NC}"
fi

# Directory to scan
scan_directory="$output_dir"

# Check if vt-cli is installed
command -v vt >/dev/null 2>&1 || { echo -e >&2 "${RED}virustotal-cli is not installed. Please install it.${NC}"; exit 1; }

# Iterate over files in the directory
for file in "$scan_directory"/*.apk; do
  # Check if the file exists
  if [[ -f "$file" ]]; then
    filename=$(basename "$file")
    echo -e "\nScanning file: ${GREEN}$filename${NC}"

    # Calculate the SHA-256 hash of the file
    file_hash=$(sha256sum "$file" | awk '{print $1}')

    # Get the scan results using vt-cli
    result=$(vt file "$file_hash" --format json | jq '.. | select(.result?) | .result' | wc -l)

    # Check if result is 0 or greater than 0 and display colored output accordingly
    if [[ $result -eq 0 ]]; then
      echo -e "Result: ${GREEN}Safe${NC} (0 detections)"
      safe_count=$((safe_count + 1))
    else
      echo -e "Result: ${RED}Malicious${NC} ($result detections)"
      malicious_count=$((malicious_count + 1))
    fi
  fi
done

echo
echo "Scan completed."
echo -e "Total APKs extracted: $extracted_count"
echo -e "${RED}Malicious APKs: $malicious_count${NC}"
echo -e "${GREEN}Safe APKs: $safe_count${NC}"
