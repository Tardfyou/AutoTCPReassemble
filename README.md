# AutoTCPReassemble

**Huazhong University of Science and Technology**  
2025 Spring Network and System Security Course Design – Continuously Optimized Version

## Overview

**AutoTCPReassemble** is a tool for TCP stream reassembly and script-based malicious code detection. It offers two primary functionalities:

1. **TCP Stream Reassembly**: This feature allows the reassembly of data from captured network traffic (PCAP files). It works by processing the TCP packets and reconstructing the transmitted file. The reconstructed file can then be compared with the original file (with a `.orig` extension) to verify integrity using `md5sum` or `diff`.

2. **Malicious Code Automation Detection**: This feature supports automated analysis of potential malicious code in scripts. It involves manual analysis of a test file (`cs-test.2`), followed by an automated analysis using Python plugins in IDA Pro. The final step includes dynamic validation of the exploit and malicious code by running a QEMU-based virtual machine.

## Prerequisites

- **PCAP Files**: The program expects network traffic data in the PCAP format.
- **IDA Pro**: Required for running Python scripts that analyze malicious code.
- **QEMU**: Needed to create a virtual machine for dynamic analysis and exploit verification.
- **Make**: Used for building the project from the source code.

## Installation

1. Clone this repository:

    ```bash
    git clone https://github.com/yourusername/AutoTCPReassemble.git
    cd AutoTCPReassemble
    ```

2. Build the project (this will generate the `pcapdata` executable):

    ```bash
    make
    ```

## Usage

### 1. TCP Stream Reassembly

To reassemble a TCP stream and compare it with the original file:

1. Run the `pcapdata` executable with the required command line arguments. You will need to specify the PCAP file containing the traffic and optionally the `.orig` file for comparison.

    ```bash
    ./pcapdata <input_pcap_file>
    ```

    Example:

    ```bash
    ./pcapdata test.pcap
    ```

2. The program will process the TCP packets in the provided PCAP file, reassemble the stream, and compare the result with the `.orig` file. It will output a comparison result using `md5sum` or `diff` to verify whether the reassembled data matches the original source file.

### 2. Script-based Malicious Code Detection

This feature focuses on detecting and analyzing malicious code in scripts.

1. **Manual Analysis**:

    - Start by manually analyzing the file `cs-test.2`. This can be done by inspecting the script for suspicious or unusual behavior.
  
2. **Automated Analysis in IDA**:

    - Run the provided Python plugin script in IDA Pro to automate the analysis of the malicious code.
    
    Example:

    ```bash
    python analyze_malicious_code.py cs-test.2
    ```

    - The script will analyze the code and generate a report detailing potential vulnerabilities, malicious patterns, and other suspicious activity.
    
3. **Dynamic Validation in QEMU**:

    - Once the malicious code has been identified, use QEMU to create a virtual machine and test the exploit and the behavior of the malicious code dynamically.

    Example:

    ```bash
    qemu-system-x86_64 -hda exploit_disk_image.qcow2
    ```

    - This step allows you to observe how the malicious code executes in a controlled environment and verify its impact on the system.

## Features

- **TCP Stream Reassembly**: Reconstructs data from network traffic, allowing you to retrieve the transmitted file and compare it with the original.
- **Malicious Code Detection**: Uses a combination of manual and automated techniques to identify and analyze malicious code in scripts.
- **Automated Reports**: The system generates detailed reports for both TCP reassembly and malicious code analysis.
- **Dynamic Validation**: Using QEMU, exploits and malicious code can be tested in a virtual machine for real-time analysis.

## Example Output

- **TCP Stream Reassembly**:

    If the reassembled file matches the original, the output might look like:

    ```bash
    [INFO] Packet inserted: seq=12345, length=500
    [INFO] File reassembly completed successfully.
    [INFO] Reconstructed file matches the original.
    ```

    If there is a discrepancy, a warning will be shown:

    ```bash
    [WARNING] Missing data detected, expected seq: 12345, found seq: 12346
    ```

- **Malicious Code Detection**:

    After running the analysis script, the report might look like:

    ```bash
    [INFO] Script analysis completed.
    [INFO] Potential exploit found at address 0x0045a0.
    [WARNING] Suspicious API call detected: system("rm -rf /").
    ```

## Contributing

Feel free to fork this repository, open issues, or submit pull requests. If you have improvements or bug fixes, your contributions are welcome!

## License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.
