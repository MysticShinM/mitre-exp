import csv
import json
import requests

# URL to fetch MITRE ATT&CK Enterprise data
MITRE_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# Reference data for Data Source ID and Name
reference_data = [
    {"ID": "DS0029", "Name": "Network Traffic"},
    {"ID": "DS0030", "Name": "Instance"},
    {"ID": "DS0019", "Name": "Service"},
    {"ID": "DS0022", "Name": "File"},
    {"ID": "DS0009", "Name": "Process"},
    {"ID": "DS0002", "Name": "User Account"},
    {"ID": "DS0006", "Name": "Web Credential"},
    {"ID": "DS0035", "Name": "Internet Scan"},
    {"ID": "DS0028", "Name": "Logon Session"},
    {"ID": "DS0024", "Name": "Windows Registry"},
    {"ID": "DS0017", "Name": "Command"},
    {"ID": "DS0010", "Name": "Cloud Storage"},
    {"ID": "DS0003", "Name": "Scheduled Job"},
    {"ID": "DS0026", "Name": "Active Directory"},
    {"ID": "DS0032", "Name": "Container"},
    {"ID": "DS0023", "Name": "Named Pipe"},
    {"ID": "DS0011", "Name": "Module"},
    {"ID": "DS0027", "Name": "Driver"},
    {"ID": "DS0016", "Name": "Drive"},
    {"ID": "DS0015", "Name": "Application Log"},
    {"ID": "DS0012", "Name": "Script"},
    {"ID": "DS0037", "Name": "Certificate"},
    {"ID": "DS0001", "Name": "Firmware"},
    {"ID": "DS0020", "Name": "Snapshot"},
    {"ID": "DS0025", "Name": "Cloud Service"},
    {"ID": "DS0036", "Name": "Group"},
    {"ID": "DS0007", "Name": "Image"},
    {"ID": "DS0004", "Name": "Malware Repository"},
    {"ID": "DS0013", "Name": "Sensor Health"},
    {"ID": "DS0033", "Name": "Network Share"},
    {"ID": "DS0005", "Name": "WMI"},
    {"ID": "DS0038", "Name": "Domain Name"},
    {"ID": "DS0008", "Name": "Kernel"},
    {"ID": "DS0021", "Name": "Persona"},
    {"ID": "DS0018", "Name": "Firewall"},
    {"ID": "DS0034", "Name": "Volume"},
    {"ID": "DS0014", "Name": "Pod"},
    {"ID": "DS0031", "Name": "Cluster"}
]

# Mapping for Tactic ID and Name (using hyphens in names)
tactic_mapping = {
    "collection": "TA0009",
    "command-and-control": "TA0011",
    "credential-access": "TA0006",
    "defense-evasion": "TA0005",
    "discovery": "TA0007",
    "execution": "TA0002",
    "exfiltration": "TA0010",
    "impact": "TA0040",
    "initial-access": "TA0001",
    "lateral-movement": "TA0008",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "reconnaissance": "TA0043",
    "resource-development": "TA0042"
}


def fetch_mitre_data():
    """
    Fetch MITRE ATT&CK data from the official GitHub repository.
    Returns the JSON data.
    """
    response = requests.get(MITRE_ATTACK_URL)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception("Failed to fetch MITRE ATT&CK data.")


def map_data_sources_to_techniques(mitre_data, reference_data, tactic_mapping):
    """
    Map data source IDs and names to techniques, including tactics and subnames.
    """
    mappings = []
    objects = mitre_data.get("objects", [])

    for obj in objects:
        if obj.get("type") == "attack-pattern":  # Technique objects
            technique_id = next((ref.get("external_id") for ref in obj.get("external_references", []) if
                                 ref.get("source_name") == "mitre-attack"), "N/A")
            technique_name = obj.get("name", "N/A")
            detection = obj.get("x_mitre_detection", "N/A")
            data_sources = obj.get("x_mitre_data_sources", [])
            kill_chain_phases = obj.get("kill_chain_phases", [])

            for tactic in kill_chain_phases:
                raw_tactic_name = tactic.get("phase_name", "N/A")  # Tactic name as-is
                normalized_tactic_name = raw_tactic_name.replace(" ",
                                                                 "-").lower()  # Replace spaces with hyphens and lowercase
                tactic_id = tactic_mapping.get(normalized_tactic_name, "N/A")  # Get Tactic ID from the mapping

                for data_source_name in data_sources:  # Data sources in <main name>:<subname> format
                    parts = data_source_name.split(":")  # Split into main name and subname
                    main_name = parts[0]
                    subname = parts[1] if len(parts) > 1 else "N/A"  # Handle missing subname

                    # Match the main name with the reference data
                    matched_reference = next((item for item in reference_data if item["Name"] == main_name), None)

                    if matched_reference:
                        mappings.append({
                            "Data Source ID": matched_reference["ID"],
                            "Data Source Name": matched_reference["Name"],
                            "Data Source Event": subname,
                            "Tactic ID": tactic_id,
                            "Tactic Name": raw_tactic_name,
                            "Technique ID": technique_id,
                            "Technique Name": technique_name,
                            "Detection": detection
                        })

    return mappings


def save_to_csv(mappings, output_file="mapped_data_sources_with_TTP's.csv"):
    """
    Save the mapped data to a CSV file.
    """
    with open(output_file, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=[
            "Data Source ID", "Data Source Name",
            "Data Source Event", "Tactic ID", "Tactic Name",
            "Technique ID", "Technique Name", "Detection"
        ])
        writer.writeheader()
        writer.writerows(mappings)
    print(f"Data successfully saved to {output_file}")


if __name__ == "__main__":
    try:
        # Fetch the MITRE ATT&CK data
        mitre_data = fetch_mitre_data()

        # Map data sources to techniques and tactics
        mapped_data = map_data_sources_to_techniques(mitre_data, reference_data, tactic_mapping)

        # Save the results to a CSV file
        save_to_csv(mapped_data)
    except Exception as e:
        print(f"Error: {e}")
