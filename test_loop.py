# from agent import client, TOOLS, TOOL_FUNCTIONS
# from config import MODEL_NAME
# from google.genai import types

# email = """
# From: security@paypa1-support.com

# Subject:
# Urgent! Verify your account

# Body:
# Click immediately.

# Link:
# http://192.168.1.15/login
# """

# response = client.models.generate_content(
#     model=MODEL_NAME,
#     contents=email,
#     config=types.GenerateContentConfig(
#         system_instruction="""
# You are a cybersecurity analyst.

# Use tools whenever needed.
# """,
#         tools=TOOLS,
#     ),
# )

# candidate = response.candidates[0]

# part = candidate.content.parts[0]

# print(part.function_call)

# function_call = part.function_call

# tool_name = function_call.name

# arguments = dict(function_call.args)

# print(tool_name)

# print(arguments)

# result = TOOL_FUNCTIONS[tool_name](**arguments)

# print()

# print(result)