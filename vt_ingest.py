# -*- coding: utf-8 -*-
# VirusTotal Hash Checker Ingest Module for Autopsy

# Autopsy & SleuthKit Imports
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter, FileIngestModule
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.ingest import IngestServices, IngestMessage
from java.io import File

# Custom imports
from vt_tag import tag_file_with_vt_status
from vt_blackboard_helper import post_virustotal_artifact
from vt_reporter import VTReporter

# Python imports
import hashlib
import json
import urllib2
from jarray import zeros  # For Java byte[] buffer

class VTScannerModuleFactory(IngestModuleFactoryAdapter):

    def getModuleDisplayName(self):
        return "VirusTotal Malware Scanner"

    def getModuleDescription(self):
        return (
            "Checks SHA-256 hashes of files against the VirusTotal database. "
            "Flags malicious files based on detection count and generates CSV, JSON, "
            "and HTML reports in the case's report directory. VirusTotal links are included "
            "for each malicious file."
        )

    def getModuleVersionNumber(self):
        return "1.0"

    def isFileIngestModuleFactory(self):
        return True

    def createFileIngestModule(self, settings):
        return VTScannerModule()



class VTScannerModule(FileIngestModule):

    def __init__(self):
        self.logger = Logger.getLogger("VTScanner")
        self.api_key = "40e06f563f64ce2fa251d6e3feb58095090634caa677919aacf54da0177c9d80"
        self.reporter = None

    def startUp(self, context):
        if not self.api_key:
            self.logger.severe("VirusTotal API key not set")
            return

        case = Case.getCurrentCase()
        report_subdir = File(case.getReportDirectory(), "VirusTotal")
        report_subdir.mkdirs()
        self.reporter = VTReporter(report_subdir.getAbsolutePath(), self.logger)

    def shutDown(self):
        if self.reporter:
            self.reporter.export()

            services = IngestServices.getInstance()
            message = "VirusTotal reports generated:\n\n"
            message += "📄 HTML: {}\n".format(self.reporter.html_file)
            message += "📄 CSV: {}\n".format(self.reporter.csv_file)
            message += "📄 JSON: {}\n".format(self.reporter.json_file)

            services.postMessage(IngestMessage.createMessage(
                IngestMessage.MessageType.INFO,
                "VirusTotal Scanner",
                message
            ))

    def process(self, file):
        if not file.isFile() or file.getSize() == 0:
            return FileIngestModule.ProcessResult.OK

        sha256_hash = self.compute_sha256(file)
        if sha256_hash is None:
            self.logger.severe("Failed to compute SHA-256 for file: " + file.getName())
            return FileIngestModule.ProcessResult.OK

        url = "https://www.virustotal.com/api/v3/files/" + sha256_hash
        headers = {"x-apikey": self.api_key}

        try:
            req = urllib2.Request(url, headers=headers)
            response = urllib2.urlopen(req)
            json_data = json.load(response)

            stats = json_data["data"]["attributes"]["last_analysis_stats"]
            total_detections = stats.get("malicious", 0)
            file_name = file.getName()
            file_path = file.getParentPath()
            is_malicious = total_detections > 0

            if is_malicious:
                self.logger.severe("[MALICIOUS] File: {} | SHA256: {} | Detections: {}".format(
                    file_name, sha256_hash, total_detections))

                report_url = "https://www.virustotal.com/gui/file/" + sha256_hash
                post_virustotal_artifact(file, sha256_hash, total_detections, report_url, self.logger)
                tag_file_with_vt_status(file, total_detections, sha256_hash, report_url, self.logger)
                self.reporter.add_entry(file_name, file_path, total_detections, sha256_hash, report_url)

        except urllib2.HTTPError as e:
            if e.code == 404:
                self.logger.info("File not found on VirusTotal: " + sha256_hash)
            else:
                self.logger.severe("VirusTotal request failed: HTTP Error {}".format(e.code))

        return FileIngestModule.ProcessResult.OK

    def compute_sha256(self, file):
        BUFFER_SIZE = 8192
        digest = hashlib.sha256()
        stream = None

        try:
            stream = ReadContentInputStream(file)
            buffer = zeros(BUFFER_SIZE, 'b')

            while True:
                read_len = stream.read(buffer)
                if read_len == -1:
                    break
                digest.update(buffer[:read_len])
        except Exception as e:
            self.logger.severe("Error computing SHA-256: " + str(e))
            return None
        finally:
            if stream is not None:
                stream.close()

        return digest.hexdigest()
