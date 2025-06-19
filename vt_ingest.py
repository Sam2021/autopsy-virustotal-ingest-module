# -*- coding: utf-8 -*-

from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter, FileIngestModule, IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleReferenceCounter
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.datamodel import ReadContentInputStream


import hashlib
import json
import urllib2
from jarray import zeros
from java.lang import Byte
from java.io import ByteArrayOutputStream


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

        self.api_key = "YOUR_API_KEY"


    def startUp(self, context):
        if not self.api_key:
            self.logger.severe("VirusTotal API key not set")
            return

    def process(self, file):
        if not file.isFile() or file.getSize() == 0:
            return FileIngestModule.ProcessResult.OK

        sha256_hash = self.compute_sha256(file)
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

            if total_detections > 0:
                self.logger.severe("[MALICIOUS] File: {} | SHA256: {} | Detections: {}".format(
                    file_name, sha256_hash, total_detections))
            else:
                self.logger.info("[CLEAN] File: {} | SHA256: {} | Detections: {}".format(
                    file_name, sha256_hash, total_detections))
        except Exception as e:
            self.logger.severe("VirusTotal request failed: " + str(e))

        return FileIngestModule.ProcessResult.OK

    def compute_sha256(self, file):
        BUFFER_SIZE = 8192

        stream = ReadContentInputStream(file)

        digest = hashlib.sha256()

        try:
            buffer = bytearray(BUFFER_SIZE)
            while True:
                read_len = stream.read(buffer)
                if read_len == -1 or read_len == 0:
                    break
                digest.update(bytes(buffer[:read_len]))  # FIXED line
        finally:
            stream.close()

        return digest.hexdigest()

