import csv
def parse_openvas_csv(csv_file):
    vulnerabilities=[]
    with open(csv_file, newline='', encoding='utf-8') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            vulnerability = {
                "ip": row["IP"],
                "hostname": row["Hostname"],
                "port": row["Port"],
                "protocol": row["Port Protocol"],
                "cvss": row["CVSS"],
                "severity": row["Severity"],
                "nvt_name": row["NVT Name"],
                "summary": row["Summary"],
                "specific_result": row["Specific Result"],
                "nvt_oid": row["NVT OID"],
                "cves": row["CVEs"],
                "task_id": row["Task ID"],
                "task_name": row["Task Name"],
                "timestamp": row["Timestamp"],
                "result_id": row["Result ID"],
                "impact": row["Impact"],
                "solution": row["Solution"],
                "affected_software": row["Affected Software/OS"],
                "vulnerability_insight": row["Vulnerability Insight"],
                "detection_method": row["Vulnerability Detection Method"],
                "product_detection_result": row["Product Detection Result"],
                "bids": row["BIDs"],
                "certs": row["CERTs"],
                "other_references": row["Other References"],
            }
            vulnerabilities.append(vulnerability)
    return vulnerabilities
if __name__ == "__main__":
    openvas_csv_file = input("Enter the name of the OpenVAS CSV file: ")
    vulnerabilities = parse_openvas_csv(openvas_csv_file)
    output_file = "report.csv"
    with open(output_file, mode='w' , encoding='utf-8') as out_file:
        for vulnerability in vulnerabilities:
            out_file.write(f"IP: {vulnerability['ip']}\n")
            out_file.write(f"Port: {vulnerability['port']}\n")
            out_file.write(f"Protocol: {vulnerability['protocol']}\n")
            out_file.write(f"CVSS: {vulnerability['cvss']}\n")
            out_file.write(f"Severity: {vulnerability['severity']}\n")
            out_file.write(f"NVT Name: {vulnerability['nvt_name']}\n")
            out_file.write(f"Summary: {vulnerability['summary']}\n")
            out_file.write(f"Impact: {vulnerability['impact']}\n")
            out_file.write(f"Solution: {vulnerability['solution']}\n")
            out_file.write(f"CVEs: {vulnerability['cves']}\n")
            out_file.write(f"Task ID: {vulnerability['task_id']}\n")
            out_file.write(f"Timestamp: {vulnerability['timestamp']}\n")
            out_file.write(f"Result ID: {vulnerability['result_id']}\n")
            out_file.write(f"Affected Software/OS: {vulnerability['affected_software']}\n")
            out_file.write(f"Other References: {vulnerability['other_references']}\n")
        print(f"Report successfully written to {output_file}")
            
