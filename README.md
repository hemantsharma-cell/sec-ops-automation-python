# Security Automation: OpenVAS to Snort IDS Pipeline

### **Project Overview**
This project provides an automated backend pipeline to bridge the gap between vulnerability scanning and active network defense. [cite_start]It transforms raw **OpenVAS** scan reports into actionable **Snort IDS** rules, reducing manual configuration time and accelerating incident response.

### **The Technical Pipeline**
The workflow is divided into two distinct stages to ensure data integrity and modularity:

1. **Stage 1: Data Parsing (`01_parser.py`)** - Ingests raw CSV exports from OpenVAS.
   - Extracts critical fields: CVE IDs, target ports, and threat levels.
   - Outputs a refined dataset for rule generation.

2. **Stage 2: Rule Generation (`02_generator.py`)** - Consumes the refined dataset.
   - Applies logic to generate valid Snort signature syntax.
   - Produces a `.rules` file ready for immediate network deployment.

### **Key Skills Demonstrated**
- **Backend Engineering**: Scripting complex data transformations using Python.
- **Security Analytics**: Performing full analysis of vulnerability data to inform defense posture.
- **Efficiency**: Automating rule deployment to meet internal security SLAs.

### **How to Run**
1. Place your OpenVAS CSV in `data/raw/`.
2. Run the parser: `python src/01_parser.py`
3. Run the generator: `python src/02_generator.py`
4. Find your rules in `output/`.
