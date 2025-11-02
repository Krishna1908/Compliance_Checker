from openai import AzureOpenAI
 
# Initialize AzureOpenAI client
client = AzureOpenAI(
    api_key="sk-yNb_S9JHvok6NQMFS-u7sQ",
    api_version="2024-02-15-preview",
    azure_endpoint="https://genai-sharedservice-americas.pwc.com"
)
 
# Test the key with a simple prompt
try:
    response = client.chat.completions.create(
        model="azure.gpt-4o",  # This is your deployment name
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Hello, are you working?"}
        ]
    )
    print("✅ Key is working. Response:")
    print(response.choices[0].message.content)
except Exception as e:
    print("❌ Key might not be working. Error:")
    print(e)
