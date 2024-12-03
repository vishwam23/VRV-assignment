import re
import csv
from collections import Counter, defaultdict

# Threshold for flagging suspicious IPs
THRESHOLD = 10

def read_log(file_path):
    """Read the log file and return its content as a list of lines."""
    with open(file_path, 'r') as log_file:
        return log_file.readlines()

def analyze_requests_by_ip(log_data):
    """Analyze and count requests per IP address."""
    ip_counts = Counter()
    for entry in log_data:
        ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', entry)
        if ip_match:
            ip_counts[ip_match.group()] += 1
    return ip_counts.most_common()

def find_top_endpoint(log_data):
    """Find the most frequently accessed endpoint."""
    endpoint_usage = Counter()
    for entry in log_data:
        match = re.search(r'\"(?:GET|POST|PUT|DELETE) (/[^\s]*)', entry)
        if match:
            endpoint_usage[match.group(1)] += 1
    return endpoint_usage.most_common(1)[0] if endpoint_usage else ("None", 0)

def detect_failed_logins(log_data):
    """Detect suspicious activity based on failed login attempts."""
    failed_ips = defaultdict(int)
    for entry in log_data:
        if "401" in entry or "Invalid credentials" in entry:
            ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', entry)
            if ip_match:
                failed_ips[ip_match.group()] += 1
    return {ip: count for ip, count in failed_ips.items() if count > THRESHOLD}

def save_results_to_csv(results, file_name):
    """Save analysis results to a CSV file."""
    with open(file_name, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)

        # IP Requests
        writer.writerow(["Requests Per IP"])
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(results["ip_requests"])
        writer.writerow([])

        # Top Endpoint
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(results["top_endpoint"])
        writer.writerow([])

        # Suspicious Activity
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        writer.writerows(results["suspicious_ips"].items())

def main():
    log_file_path = "sample.log"
    log_entries = read_log(log_file_path)

    # Analysis
    ip_requests = analyze_requests_by_ip(log_entries)
    top_endpoint = find_top_endpoint(log_entries)
    suspicious_ips = detect_failed_logins(log_entries)

    # Display results
    print("IP Address           Request Count")
    for ip, count in ip_requests:
        print(f"{ip:<20}{count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{top_endpoint[0]} (Accessed {top_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, attempts in suspicious_ips.items():
        print(f"{ip:<20}{attempts}")

    # Save results
    results = {
        "ip_requests": ip_requests,
        "top_endpoint": top_endpoint,
        "suspicious_ips": suspicious_ips,
    }
    save_results_to_csv(results, "log_analysis_results.csv")

if __name__ == "__main__":
    main()
