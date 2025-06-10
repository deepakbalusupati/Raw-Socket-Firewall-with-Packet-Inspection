from flask import Flask, render_template, request, jsonify
import subprocess
import os
import json
import sys
import platform

app = Flask(__name__)

# Platform-specific configuration
is_windows = platform.system() == 'Windows'
firewall_executable = 'firewall.exe' if is_windows else 'firewall'
app.config['FIREWALL_PATH'] = os.path.join(os.path.dirname(__file__), '..', 'build', firewall_executable)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/firewall/start', methods=['POST'])
def start_firewall():
    interface = request.json.get('interface', 'eth0')
    try:
        # In a real implementation, you would properly manage the process
        subprocess.Popen([app.config['FIREWALL_PATH'], interface])
        return jsonify({'status': 'success', 'message': f'Firewall started on {interface}'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/firewall/stop', methods=['POST'])
def stop_firewall():
    try:
        # Platform-specific process termination
        if is_windows:
            subprocess.run(['taskkill', '/F', '/IM', firewall_executable])
        else:
            subprocess.run(['pkill', '-f', 'firewall'])
        return jsonify({'status': 'success', 'message': 'Firewall stopped'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/firewall/rules', methods=['GET', 'POST'])
def manage_rules():
    rules_file = os.path.join(os.path.dirname(__file__), '..', 'config', 'firewall.rules')
    
    if request.method == 'GET':
        try:
            with open(rules_file, 'r') as f:
                rules = f.readlines()
            return jsonify({'status': 'success', 'rules': rules})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            rules = request.json.get('rules', [])
            with open(rules_file, 'w') as f:
                f.writelines(rules)
            return jsonify({'status': 'success', 'message': 'Rules updated'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/interfaces', methods=['GET'])
def get_interfaces():
    try:
        interfaces = []
        
        # Platform-specific interface detection
        if is_windows:
            import psutil
            for iface, addrs in psutil.net_if_addrs().items():
                interfaces.append(iface)
        else:
            import netifaces
            interfaces = netifaces.interfaces()
            
        return jsonify({'status': 'success', 'interfaces': interfaces})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)