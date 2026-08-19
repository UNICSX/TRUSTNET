from google.genai import types
import inspect

print(inspect.signature(types.Part.from_function_response))
print()
print(types.Part.from_function_response.__doc__)