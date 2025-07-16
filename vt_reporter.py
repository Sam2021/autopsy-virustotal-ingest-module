# vt_reporter.py
# -*- coding: utf-8 -*-

import os
import csv
import json

class VTReporter:
    def __init__(self, report_dir, logger):
        self.logger = logger
        self.entries = []
        self.report_dir = report_dir
        self.csv_file = os.path.join(report_dir, "malicious_files_report.csv")
        self.json_file = os.path.join(report_dir, "malicious_files_report.json")
        self.html_file = os.path.join(report_dir, "malicious_files_report.html")

    def add_entry(self, name, path, detections, sha256, vt_url):
        self.entries.append({
            "file_name": name,
            "file_path": path,
            "detections": detections,
            "sha256": sha256,
            "vt_url": vt_url
        })

    def export(self):
        if not self.entries:
            self.logger.info("No malicious files to report.")
            return

        try:
            # CSV
            with open(self.csv_file, "w") as f:
                writer = csv.DictWriter(f, fieldnames=self.entries[0].keys())
                writer.writeheader()
                writer.writerows(self.entries)

            # JSON
            with open(self.json_file, "w") as f:
                json.dump(self.entries, f, indent=4)

            # HTML
            with open(self.html_file, "w") as f:
                f.write("<html><head><title>VirusTotal Report</title></head><body>")
                f.write("<h2>Malicious Files Report</h2>")
                f.write("<table border='1' style='border-collapse: collapse;'>")
                f.write("<tr><th>File Name</th><th>Path</th><th>Detections</th><th>SHA256</th><th>VirusTotal Link</th></tr>")
                for entry in self.entries:
                    f.write("<tr>")
                    f.write("<td>{}</td>".format(entry["file_name"]))
                    f.write("<td>{}</td>".format(entry["file_path"]))
                    f.write("<td>{}</td>".format(entry["detections"]))
                    f.write("<td>{}</td>".format(entry["sha256"]))
                    f.write("<td><a href='{}'>Link</a></td>".format(entry["vt_url"]))
                    f.write("</tr>")
                f.write("</table></body></html>")

            self.logger.info("VT report exported: CSV, JSON, and HTML")

        except Exception as e:
            self.logger.severe("Failed to write VT report: " + str(e))
