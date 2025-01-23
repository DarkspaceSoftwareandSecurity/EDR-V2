

# EDR-V2 ENDPOINT DETECTION & RESPONSE 






![Capture](https://github.com/user-attachments/assets/bb1e5c8a-8233-49b9-b0db-e7195fbe0a98)









Documentation for EDR Automated Script
Overview
This Python script serves as an Automated Endpoint Detection and Response (EDR) tool, integrating several monitoring functionalities: process monitoring, file monitoring, network traffic monitoring, and visual graphing. It provides real-time analysis of system resources, logs file system activity, and captures network packet sizes. The data is presented in a GUI interface and can be saved as a report in a .docx format.

Features:
Process Monitoring: Monitors CPU and memory usage, updates graphs, and logs performance data.
File Monitoring: Tracks file creation, deletion, and modification in the working directory.
Network Traffic Monitoring: Captures packet sizes and logs network activity.
Visual Graphing: Displays CPU usage, memory usage, and network traffic trends using Matplotlib.
Report Generation: Creates and saves an .docx report with monitored data (CPU, memory, file activity, and network traffic).
Real-time Log Updates: Displays logs for ongoing monitoring activities.
Graphical User Interface (GUI): Developed using Tkinter, enabling users to control the system (start/stop monitoring) and view results visually.
Dependencies
psutil: For system resource monitoring (CPU, memory).
watchdog: For file system monitoring.
scapy: For network packet sniffing.
docx: To generate Word document reports.
matplotlib: For graphing system resource usage trends.
tkinter: For building the GUI.
Use Cases
1. Start Monitoring
Objective: Begin system monitoring for CPU, memory, file activity, and network traffic.
How to Use:
Click the "Start Monitoring" button in the GUI.
The system will start monitoring processes, files, and network traffic.
Data will be continuously updated in the log area and graphs will display usage trends.
Expected Outcome:
CPU and memory usage graphs update in real-time.
File activities (create, modify, delete) are logged.
Network traffic data is recorded.
2. Stop Monitoring
Objective: Stop ongoing monitoring.
How to Use:
Click the "Stop Monitoring" button in the GUI.
The system will stop all threads for monitoring.
Expected Outcome:
Monitoring threads will terminate.
The program will display a confirmation message: "Monitoring stopped."
3. Generate Report
Objective: Create a report of the monitoring session in a .docx format.
How to Use:
Click the "Generate Report" button in the GUI.
The system will compile CPU usage, memory usage, file activity, and network traffic into a report.
Expected Outcome:
A .docx file titled EDR_Report.docx is saved in the current directory.
The report includes sections for CPU and memory usage trends, file activity logs, and network traffic analysis.
4. Visualize Resource Usage
Objective: Visual representation of system resource usage.
How to Use:
After starting monitoring, the graphs update automatically.
The graphs display CPU usage, memory usage, and network traffic over time.
Expected Outcome:
Real-time graphs that allow users to visually monitor system resource trends.
5. File Activity Monitoring
Objective: Track changes in the file system (file creation, deletion, modification).
How to Use:
File activities are logged automatically when they occur within the monitored directory.
View logs for file activity in the log area of the GUI.
Expected Outcome:
The log area will display detailed messages about file activities (e.g., "File created: filename").
6. Network Traffic Monitoring
Objective: Monitor network traffic by sniffing packets.
How to Use:
After starting monitoring, the system will automatically capture network packets.
The packet sizes are logged and visualized in the network traffic graph.
Expected Outcome:
Network traffic trends are displayed, with packet sizes logged in the log area.
GUI Interface
Top Frame: Contains the title of the script.
Log Area: A scrollable text area that displays ongoing logs of file activities, system resource usage, and network packet captures.
Graph Area: Displays real-time graphs for CPU usage, memory usage, and network traffic.
Control Buttons:
Start Monitoring: Begins monitoring processes, files, and network traffic.
Stop Monitoring: Stops the ongoing monitoring.
Generate Report: Generates and saves a report in .docx format.
Exit: Closes the application.
Example Scenarios
Detecting Unusual File Modifications: A user can monitor file changes in a directory where sensitive files are stored. If there are unexpected file deletions or modifications, the log will provide alerts for further investigation.

Tracking System Resource Usage: During high-demand tasks, users can monitor CPU and memory usage to ensure optimal system performance. The graphs provide visual trends over time, helping users identify bottlenecks.

Network Traffic Analysis: This can be useful for monitoring abnormal network activity, such as large packet sizes indicative of a potential data exfiltration attempt.

Generating Reports for Audits: After a monitoring session, the user can generate a detailed report that summarizes the monitored data, which can be used for audit purposes or further investigation.
