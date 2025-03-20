from flask import Flask, request, jsonify, render_template, send_from_directory
import socket
import threading
import time
from datetime import datetime
import os
import json

app = Flask(__name__)

# Port scanner function from the previous code
def scan_port(target_ip, port, timeout=1):
    """
    Scan a single port on the target IP.
    Returns (port, is_open, service_name) tuple.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    result = sock.connect_ex((target_ip, port))
    is_open = result == 0
    
    service_name = ""
    if is_open:
        try:
            service_name = socket.getservbyport(port)
        except:
            service_name = "unknown"
    
    sock.close()
    return (port, is_open, service_name)

def scan_ports(target, port_range=None, num_threads=100, timeout=1):
    """
    Scan a range of ports on the target.
    
    Args:
        target: IP address or hostname to scan
        port_range: Tuple of (start_port, end_port) or None for common ports
        num_threads: Number of concurrent threads to use
        timeout: Connection timeout in seconds
    
    Returns:
        Dictionary with scan results
    """
    # Common ports to scan if no range specified
    common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                   993, 995, 1723, 3306, 3389, 5900, 8080]
    
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return {"error": f"Could not resolve hostname '{target}'"}
    
    # Determine which ports to scan
    if port_range:
        start_port, end_port = port_range
        ports_to_scan = range(start_port, end_port + 1)
    else:
        ports_to_scan = common_ports
    
    start_time = time.time()
    
    # Results will be stored here
    results = []
    
    # Use a semaphore to limit the number of concurrent threads
    thread_limiter = threading.Semaphore(num_threads)
    threads = []
    
    def scan_port_worker(port):
        thread_limiter.acquire()
        try:
            result = scan_port(target_ip, port, timeout)
            if result[1]:  # If port is open
                results.append(result)
        finally:
            thread_limiter.release()
    
    # Start threads for scanning
    for port in ports_to_scan:
        thread = threading.Thread(target=scan_port_worker, args=(port,))
        threads.append(thread)
        thread.start()
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    # Sort results by port number
    results.sort()
    
    # Format results for JSON response
    formatted_results = []
    for port, is_open, service_name in results:
        formatted_results.append({
            "port": port,
            "state": "open" if is_open else "closed",
            "service": service_name
        })
    
    elapsed_time = time.time() - start_time
    
    return {
        "target": target,
        "target_ip": target_ip,
        "scan_time": elapsed_time,
        "start_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "open_ports": formatted_results,
        "total_open_ports": len(formatted_results)
    }

# Create a directory for templates if it doesn't exist
os.makedirs('templates', exist_ok=True)

# Write the HTML to a template file
@app.route('/')
def index():
    return render_template('index.html')

# API endpoint for scanning ports
@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.json
    
    if not data or 'target' not in data:
        return jsonify({"error": "Missing required parameters"}), 400
    
    target = data.get('target')
    port_range = data.get('portRange')
    timeout = float(data.get('timeout', 1))
    threads = int(data.get('threads', 100))
    
    # Validate and convert port range
    if port_range:
        try:
            start_port = int(port_range[0])
            end_port = int(port_range[1])
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                return jsonify({"error": "Invalid port range"}), 400
            port_range = (start_port, end_port)
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid port range format"}), 400
    
    try:
        result = scan_ports(target, port_range, threads, timeout)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Write the HTML template
def create_template():
    # Read the HTML content from your artifact
    html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Port Scanner</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background-color: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }
        h1 {
            color: #2c3e50;
            margin-top: 0;
        }
        .card {
            background-color: #f9f9f9;
            border-radius: 4px;
            padding: 15px;
            margin-bottom: 20px;
            border-left: 4px solid #3498db;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: 600;
        }
        input[type="text"], input[type="number"], select {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        .port-range {
            display: flex;
            gap: 10px;
        }
        .port-range input {
            width: calc(50% - 5px);
        }
        button {
            background-color: #3498db;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }
        button:hover {
            background-color: #2980b9;
        }
        button:disabled {
            background-color: #95a5a6;
            cursor: not-allowed;
        }
        .results {
            margin-top: 20px;
            min-height: 200px;
            background-color: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 4px;
            font-family: monospace;
            overflow-x: auto;
        }
        .results-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .results-header h2 {
            margin: 0;
        }
        .clear-btn {
            background-color: #e74c3c;
            padding: 5px 10px;
            font-size: 14px;
        }
        .clear-btn:hover {
            background-color: #c0392b;
        }
        .loading {
            text-align: center;
            display: none;
        }
        .loading-spinner {
            border: 4px solid rgba(255, 255, 255, 0.3);
            border-top: 4px solid #3498db;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            animation: spin 1s linear infinite;
            margin: 10px auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .port-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        .port-table th, .port-table td {
            text-align: left;
            padding: 8px;
            border-bottom: 1px solid #555;
        }
        .port-table th {
            border-bottom: 2px solid #555;
        }
        .warning {
            color: #e74c3c;
            font-weight: bold;
        }
        .success {
            color: #2ecc71;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Network Port Scanner</h1>
        
        <div class="card">
            <h2>Instructions</h2>
            <p>This tool allows you to scan a target host for open ports. Enter an IP address or hostname, select the ports to scan, and click "Start Scan" to begin.</p>
            <p><span class="warning">Important:</span> Only scan hosts you have permission to scan. Unauthorized port scanning may be illegal in some jurisdictions.</p>
        </div>
        
        <div class="form-group">
            <label for="target">Target IP Address or Hostname:</label>
            <input type="text" id="target" placeholder="e.g., 192.168.1.1 or example.com" required>
        </div>
        
        <div class="form-group">
            <label>Port Selection:</label>
            <select id="port-selection">
                <option value="common">Common Ports</option>
                <option value="custom">Custom Port Range</option>
                <option value="all">All Ports (1-65535) - VERY SLOW</option>
            </select>
        </div>
        
        <div class="form-group port-range" id="custom-range" style="display: none;">
            <div>
                <label for="start-port">Start Port:</label>
                <input type="number" id="start-port" min="1" max="65535" value="1">
            </div>
            <div>
                <label for="end-port">End Port:</label>
                <input type="number" id="end-port" min="1" max="65535" value="1000">
            </div>
        </div>
        
        <div class="form-group">
            <label for="timeout">Connection Timeout (seconds):</label>
            <input type="number" id="timeout" min="0.1" max="10" step="0.1" value="1">
        </div>
        
        <div class="form-group">
            <label for="threads">Number of Threads:</label>
            <input type="number" id="threads" min="1" max="500" value="100">
        </div>
        
        <button id="scan-btn">Start Scan</button>
        
        <div class="loading" id="loading">
            <div class="loading-spinner"></div>
            <p>Scanning ports... This may take a while depending on the target and number of ports.</p>
        </div>
        
        <div class="results-header">
            <h2>Scan Results</h2>
            <button class="clear-btn" id="clear-btn">Clear Results</button>
        </div>
        
        <div class="results" id="results">
            <p>Results will appear here after scanning.</p>
        </div>
    </div>
    
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const targetInput = document.getElementById('target');
            const portSelection = document.getElementById('port-selection');
            const customRange = document.getElementById('custom-range');
            const startPort = document.getElementById('start-port');
            const endPort = document.getElementById('end-port');
            const timeout = document.getElementById('timeout');
            const threads = document.getElementById('threads');
            const scanBtn = document.getElementById('scan-btn');
            const clearBtn = document.getElementById('clear-btn');
            const resultsDiv = document.getElementById('results');
            const loadingDiv = document.getElementById('loading');
            
            // Toggle custom port range input visibility
            portSelection.addEventListener('change', function() {
                if (this.value === 'custom') {
                    customRange.style.display = 'flex';
                } else {
                    customRange.style.display = 'none';
                }
            });
            
            // Clear results
            clearBtn.addEventListener('click', function() {
                resultsDiv.innerHTML = '<p>Results will appear here after scanning.</p>';
            });
            
            // Perform scan
            scanBtn.addEventListener('click', function() {
                // Validate input
                if (!targetInput.value) {
                    alert('Please enter a target IP or hostname');
                    return;
                }
                
                const target = targetInput.value;
                let portRange = null;
                
                if (portSelection.value === 'custom') {
                    const start = parseInt(startPort.value);
                    const end = parseInt(endPort.value);
                    
                    if (start > end) {
                        alert('Start port must be less than or equal to end port');
                        return;
                    }
                    
                    if (end - start > 10000) {
                        if (!confirm('Scanning more than 10,000 ports may take a long time. Continue?')) {
                            return;
                        }
                    }
                    
                    portRange = [start, end];
                } else if (portSelection.value === 'all') {
                    if (!confirm('Scanning all 65,535 ports will take a very long time. Continue?')) {
                        return;
                    }
                    portRange = [1, 65535];
                }
                
                // Show loading indicator
                loadingDiv.style.display = 'block';
                scanBtn.disabled = true;
                resultsDiv.innerHTML = '<p>Scanning in progress...</p>';
                
                // Call the API
                fetch('/api/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        target: target,
                        portRange: portRange,
                        timeout: parseFloat(timeout.value),
                        threads: parseInt(threads.value)
                    })
                })
                .then(response => response.json())
                .then(data => {
                    // Process and display the results
                    if (data.error) {
                        resultsDiv.innerHTML = `<p class="warning">Error: ${data.error}</p>`;
                        return;
                    }
                    
                    let html = `<h3>Scan Results for ${data.target} (${data.target_ip})</h3>`;
                    html += `<p>Time started: ${data.start_time}</p>`;
                    html += `<p>Scan completed in ${data.scan_time.toFixed(2)} seconds</p>`;
                    
                    if (data.open_ports && data.open_ports.length > 0) {
                        html += '<table class="port-table">';
                        html += '<tr><th>PORT</th><th>STATE</th><th>SERVICE</th></tr>';
                        
                        for (const result of data.open_ports) {
                            html += `<tr>
                                <td>${result.port}</td>
                                <td class="success">${result.state}</td>
                                <td>${result.service}</td>
                            </tr>`;
                        }
                        
                        html += '</table>';
                    } else {
                        html += '<p>No open ports found.</p>';
                    }
                    
                    html += `<p><strong>Scan parameters:</strong> Timeout: ${parseFloat(timeout.value)}s, Threads: ${parseInt(threads.value)}</p>`;
                    
                    resultsDiv.innerHTML = html;
                })
                .catch(error => {
                    resultsDiv.innerHTML = `<p class="warning">Error: ${error.message}</p>`;
                })
                .finally(() => {
                    loadingDiv.style.display = 'none';
                    scanBtn.disabled = false;
                });
            });
        });
    </script>
</body>
</html>
    """
    
    # Create the template file
    with open('templates/index.html', 'w') as f:
        f.write(html_content)

if __name__ == "__main__":
    # Create the template before starting the server
    create_template()
    
    # Start the Flask server
    print("Starting Port Scanner Web Server...")
    print("Open your browser and navigate to http://127.0.0.1:5000")
    app.run(debug=True)