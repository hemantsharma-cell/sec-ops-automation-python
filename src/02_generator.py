import csv

def generate_snort_rules_from_csv(csv_file, output_file="snortrule.rules"):
    """
    Generate Snort rules from an OpenVAS vulnerability report in CSV format.
    
    Args:
        csv_file (str): The path to the input CSV file.
        output_file (str): The path to the output Snort rules file.
    """
    try:
        with open(csv_file, newline='', encoding='utf-8') as file:
            csv_reader = csv.reader(file)
            headers = next(csv_reader)  # Extract headers
            rows = list(csv_reader)  # Extract data rows

        # Ensure required headers are present
        required_headers = {"Port", "CVEs", "Severity", "NVT Name"}
        if not required_headers.issubset(headers):
            raise ValueError(f"Missing required headers: {required_headers - set(headers)}")
        
        # Process each row and generate Snort rules
        with open(output_file, mode="w", encoding="utf-8") as rule_file:
            for index, row in enumerate(rows):
                data = dict(zip(headers, row))  # Combine headers and row data into a dictionary
                
                # Extract values with defaults
                port = data.get("Port", "any") or "any"
                cve = data.get("CVEs", "N/A") or "N/A"
                severity = data.get("Severity", "Unknown")
                nvt_name = data.get("NVT Name", "Unnamed")

                # Create Snort rule message and content
                rule_message = f"OpenVAS Alert: {severity} - {nvt_name}"
                rule_content = f"USER {cve[:255]}"
                
                # Generate a unique Snort rule SID
                sid = 100000 + index

                # Format the Snort rule
                rule = f'alert tcp any any -> any {port} (msg:"{rule_message}"; content:"{rule_content}"; sid:{sid};)\n'
                rule_file.write(rule)

        print(f"Snort rules have been successfully written to {output_file}.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    input_csv = "../data/processed/refined_data.csv"
    output_rules = "../output/signatures.rules"
    generate_snort_rules_from_csv(input_csv, output_rules)

