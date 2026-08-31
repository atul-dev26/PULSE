from drain3 import TemplateMiner
from drain3.file_persistence import FilePersistence
from drain3.template_miner_config import TemplateMinerConfig

import os

# Config to store state in the root dir of the project
persistence = FilePersistence("drain3_state.json")
config = TemplateMinerConfig()
# A single global template miner instance keeps state loaded
miner = TemplateMiner(persistence_handler=persistence, config=config)

def parse_drain3(payload: bytes) -> dict:
    text = payload.decode("utf-8").strip()
    if not text:
        return {}
        
    result = miner.add_log_message(text)
    template = result["template_mined"]
    
    # Extract the wildcards
    extracted = miner.extract_parameters(template, text)
    params = [x.value for x in extracted]
    
    parsed = {
        "_is_drain3": True,
        "raw_template": template,
        "template_params": params
    }
    
    # Expose them flatly as well for naive resolution attempts
    for i, v in enumerate(params):
        parsed[f"param_{i}"] = v
        
    return parsed
