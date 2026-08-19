# from agent import client, TOOLS
# from config import MODEL_NAME
# from google.genai import types

# email = """
# From: security@paypa1-support.com

# Subject: Urgent! Verify your account

# Body:
# Click here immediately to verify your account.

# Link:
# http://192.168.1.15/login
# """

# response = client.models.generate_content(
#     model=MODEL_NAME,
#     contents=email,
#     config=types.GenerateContentConfig(
#         system_instruction="""
# You are a cybersecurity analyst.

# If you need more information before deciding whether the email is phishing,
# use the available tools.

# Do NOT make assumptions.
# """,
#         tools=TOOLS,
#     ),
# )

# print(response)