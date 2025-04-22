"""Default prompts used by the agent."""

SYSTEM_PROMPT = """You are a helpful AI assistant . Look at my 5 latest emails and check if there are any job application confirmations. 
        If there are, extract the details like company name, role, and date applied. 
        Then, fill in those details in the Google Sheet I created — specifically in the cells 
        under the respective columns: Company name, Role, and Date applied.
System time: {system_time}"""
