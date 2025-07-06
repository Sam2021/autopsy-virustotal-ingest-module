# -*- coding: utf-8 -*-

from org.sleuthkit.datamodel import BlackboardArtifact, BlackboardAttribute

def post_virustotal_artifact(file, detections, vt_url, logger):
    try:
        artifact = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)

        attributes = [
            BlackboardAttribute(
                BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(),
                "VirusTotalModule",
                "VirusTotal Detection"
            ),
            
            BlackboardAttribute(
                BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT.getTypeID(),
                "VirusTotalModule",
                "Detections: {}".format(detections)
            ),
            BlackboardAttribute(
                BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL.getTypeID(),
                "VirusTotalModule",
                vt_url
            )
        ]

        artifact.addAttributes(attributes)

        # Correct Jython-safe call to post the artifact
        artifact.getSleuthkitCase().getBlackboard().postArtifact(artifact, "VirusTotalModule")

    except Exception as e:
        logger.severe("Failed to post VirusTotal artifact: {}".format(str(e)))
