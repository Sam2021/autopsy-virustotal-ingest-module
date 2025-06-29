from org.sleuthkit.datamodel import BlackboardArtifact, BlackboardAttribute
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services

def post_virustotal_artifact(file, sha256_hash, detections, is_malicious):
    case = Case.getCurrentCase()
    skCase = case.getSleuthkitCase()

    ARTIFACT_NAME = "VirusTotal Scan Result" 
    ATTRIBUTE_PREFIX = "TSK_VT_"

    # Add or retrieve custom artifact type
    try:
        art_type = skCase.addBlackboardArtifactType(ARTIFACT_NAME, "Results from VirusTotal scan")
    except:
        art_type = skCase.getArtifactType(ARTIFACT_NAME)  # returns BlackboardArtifact.Type

    # Define and add custom attributes
    attr_types = {
        ATTRIBUTE_PREFIX + "SHA256": BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
        ATTRIBUTE_PREFIX + "DETECTIONS": BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER,
        ATTRIBUTE_PREFIX + "MALICIOUS": BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
        ATTRIBUTE_PREFIX + "URL": BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING
    }

    for attr_name, attr_type in attr_types.items():
        try:
            skCase.addArtifactAttributeType(attr_name, attr_type, attr_name)
        except:
            pass  # likely already exists

    # ✅ This is the fixed line
    artifact = skCase.getBlackboard().newArtifact(art_type.getTypeID(), file.getId())

    vt_url = "https://www.virustotal.com/gui/file/" + sha256_hash

    attributes = [
        BlackboardAttribute(skCase.getAttributeType(ATTRIBUTE_PREFIX + "SHA256"),
                            "VirusTotalScanner", sha256_hash),
        BlackboardAttribute(skCase.getAttributeType(ATTRIBUTE_PREFIX + "DETECTIONS"),
                            "VirusTotalScanner", detections),
        BlackboardAttribute(skCase.getAttributeType(ATTRIBUTE_PREFIX + "MALICIOUS"),
                            "VirusTotalScanner", "Yes" if is_malicious else "No"),
        BlackboardAttribute(skCase.getAttributeType(ATTRIBUTE_PREFIX + "URL"),
                            "VirusTotalScanner", vt_url)
    ]

    artifact.addAttributes(attributes)

    # Post to blackboard
    try:
        Services.getInstance().getBlackboard().postArtifact(artifact, "VirusTotalScanner")
    except Exception as e:
        print("Failed to post artifact to blackboard: " + str(e))

# Optional: Auto-tagging logic for visual filtering
def tag_file(file, tag_name):
    try:
        Case.getCurrentCase().getServices().getTagsManager().addTag(file, tag_name, "")
    except Exception as e:
        print("Failed to tag file: " + str(e))
