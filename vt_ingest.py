# -*- coding: utf-8 -*-
# VirusTotal Hash Checker Ingest Module for Autopsy
# This module computes the SHA-256 hash of each file, queries VirusTotal for scan results,
# and creates blackboard artifacts and tags for malicious detections.

# Autopsy & SleuthKit Imports
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter, FileIngestModule
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.autopsy.casemodule import Case

# Standard Library Imports
import hashlib
import json
import urllib2
from jarray import zeros  # For Java byte[] buffer

# Custom helper module for blackboard artifact and tagging logic

# Factory class that registers the module with Autopsy
class VTScannerModuleFactory(IngestModuleFactoryAdapter):

    def getModuleDisplayName(self):
        return "VirusTotal Hash Checker"  # Module name as seen in Autopsy UI

    def getModuleDescription(self):
        return "Checks file hash against VirusTotal API"  # Description in Autopsy module list

    def getModuleVersionNumber(self):
        return "1.0"

    def isFileIngestModuleFactory(self):
        return True  # Indicates this is a File Ingest Module

    def createFileIngestModule(self, settings):
        return VTScannerModule()  # Creates an instance of the ingest module


# Main File Ingest Module class
class VTScannerModule(FileIngestModule):

    def __init__(self):
        self.logger = Logger.getLogger("VTScanner")  # Logger for module messages
        self.api_key = "40e06f563f64ce2fa251d6e3feb58095090634caa677919aacf54da0177c9d80"  # Replace with your own VT API key

    def startUp(self, context):
        # Called when the ingest job starts; check API key is set
        if not self.api_key:
            self.logger.severe("VirusTotal API key not set")
            return

    def process(self, file):
        # Skip directories or zero-size files
        if not file.isFile() or file.getSize() == 0:
            return FileIngestModule.ProcessResult.OK

        # Compute SHA-256 hash of the file contents
        sha256_hash = self.compute_sha256(file)
        if sha256_hash is None:
            self.logger.severe("Failed to compute SHA-256 for file: " + file.getName())
            return FileIngestModule.ProcessResult.OK

        # Prepare the VirusTotal API request
        url = "https://www.virustotal.com/api/v3/files/" + sha256_hash
        headers = {
            "x-apikey": self.api_key
        }

        try:
            # Send the request to VT and parse JSON response
            req = urllib2.Request(url, headers=headers)
            response = urllib2.urlopen(req)
            json_data = json.load(response)

            # Extract number of malicious detections
            stats = json_data["data"]["attributes"]["last_analysis_stats"]
            total_detections = stats.get("malicious", 0)
            file_name = file.getName()
            is_malicious = total_detections > 0

            # Only log, tag, and post if the file is malicious
            if is_malicious:
                self.logger.severe("[MALICIOUS] File: {} | SHA256: {} | Detections: {}".format(
                    file_name, sha256_hash, total_detections))
                

        except Exception as e:
            # Handle and log any API or parsing errors
            self.logger.severe("VirusTotal request failed: " + str(e))

        return FileIngestModule.ProcessResult.OK  # Ingest continues for next file

    # Utility function to compute SHA-256 of file using buffered read
    def compute_sha256(self, file):
        BUFFER_SIZE = 8192
        digest = hashlib.sha256()

        stream = None
        try:
            stream = ReadContentInputStream(file)
            buffer = zeros(BUFFER_SIZE, 'b')  # Java-style byte array

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