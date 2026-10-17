import os

os.environ["AGENTGUARD_DB"] = ":memory:"  # tests never touch audit.db
