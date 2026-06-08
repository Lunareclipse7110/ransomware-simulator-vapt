A safe, isolated ransomware simulation built for academic VAPT study. 
Simulates file encryption behavior (Red Team) while a detection engine 
monitors entropy spikes, file renames, and modification rates in real-time 
(Blue Team). Includes a live Flask dashboard to visualize the attack as it happens.

Built with: Python, Fernet AES encryption, Watchdog, Flask, Chart.js
Purpose: Educational — runs only on dummy files inside a VM
