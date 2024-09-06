**DOS Attack Detection using C and Packet Capturing**

**Description:**
- This project aims to detect Denial of Service (DOS) attacks using C programming and packet capturing techniques. It is designed to identify abnormal traffic patterns that indicate a DOS attack on a network.
**Features:**
- Detects incoming traffic.
- Analyzes packets for irregularities.
- Flags potential DOS attacks based on predefined rules.
**Installation:**
- Clone the repository: 
git clone <your-repository-link>
- Compile the code:
gcc dos_detection.c -o dos_detection
**Usage:**
- Run the compiled program:
./dos_detection
**Dependencies:**
- Requires `libpcap` for packet capturing:
sudo apt-get install libpcap-dev
