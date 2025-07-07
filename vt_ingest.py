# -*- coding: utf-8 -*-
# VirusTotal Hash Checker Ingest Module for Autopsy

# Autopsy & SleuthKit Imports
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter, FileIngestModule
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.autopsy.casemodule import Case
from vt_tag import tag_file_with_vt_status


# Standard Library Imports
import hashlib
import json
import urllib2
from jarray import zeros  # For Java byte[] buffer

# ✅ Import external artifact helper
from vt_blackboard_helper import post_virustotal_artifact

# Factory class that registers the module with Autopsy
class VTScannerModuleFactory(IngestModuleFactoryAdapter):

    def getModuleDisplayName(self):
        return "VirusTotal Hash Checker"

    def getModuleDescription(self):
        return "Checks file hash against VirusTotal API"

    def getModuleVersionNumber(self):
        return "1.0"

    def isFileIngestModuleFactory(self):
        return True

    def createFileIngestModule(self, settings):
        return VTScannerModule()


class VTScannerModule(FileIngestModule):

    def __init__(self):
        self.logger = Logger.getLogger("VTScanner")
        self.api_key = "API_KEY"

    def startUp(self, context):
        if not self.api_key:
            self.logger.severe("VirusTotal API key not set")
            return

    def process(self, file):
        if not file.isFile() or file.getSize() == 0:
            return FileIngestModule.ProcessResult.OK

        sha256_hash = self.compute_sha256(file)
        if sha256_hash is None:
            self.logger.severe("Failed to compute SHA-256 for file: " + file.getName())
            return FileIngestModule.ProcessResult.OK

        url = "https://www.virustotal.com/api/v3/files/" + sha256_hash
        headers = {
            "x-apikey": self.api_key
        }

        try:
            req = urllib2.Request(url, headers=headers)
            response = urllib2.urlopen(req)
            json_data = json.load(response)

            stats = json_data["data"]["attributes"]["last_analysis_stats"]
            total_detections = stats.get("malicious", 0)
            file_name = file.getName()
            is_malicious = total_detections > 0

            if is_malicious:
                self.logger.severe("[MALICIOUS] File: {} | SHA256: {} | Detections: {}".format(
                    file_name, sha256_hash, total_detections))

                # ✅ Call external artifact poster
                report_url = "https://www.virustotal.com/gui/file/" + sha256_hash
                post_virustotal_artifact(file,sha256_hash, total_detections, report_url, self.logger)
                
                # ✅ Add VT Tag
                tag_file_with_vt_status(file, total_detections, sha256_hash, report_url, self.logger)


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
