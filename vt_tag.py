# -*- coding: utf-8 -*-

from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import TagsManager


def tag_file_with_vt_status(file, detection_count, sha256, vt_url, logger):
    try:
        case = Case.getCurrentCaseThrows()
        tags_manager = case.getServices().getTagsManager()

        # === Choose tag label ===
        if detection_count >= 55:
            tag_label = "VT Malicious : High Detection"
        elif detection_count >= 40:
            tag_label = "VT Malicious : Medium-High Detection"
        elif detection_count >= 25:
            tag_label = "VT Malicious : Medium Detection"
        elif detection_count >= 10:
            tag_label = "VT Malicious : Low Detection"
        else:
            tag_label = "VT Malicious : Suspicious (Low)"

        # === Get or create tag name ===
        existing_tags = tags_manager.getAllTagNames()
        tag_name_obj = None
        for tag in existing_tags:
            if tag.getDisplayName() == tag_label:
                tag_name_obj = tag
                break

        if tag_name_obj is None:
            tag_name_obj = tags_manager.addTagName(tag_label, "")

        # === Add tag to file ===
        comment = "SHA256: {}\nDetections: {}\nURL: {}".format(sha256, detection_count, vt_url)
        tags_manager.addContentTag(file, tag_name_obj, comment)

    except Exception as e:
        logger.severe("Failed to tag file: " + str(e))
