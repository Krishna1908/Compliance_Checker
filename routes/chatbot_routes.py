from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Dict, Any
import asyncio
import os
import json
from openai import AzureOpenAI
import traceback
import httpx
from services.scan_service import ScanService
import logging
 
 
import re
 
# Request/Response models
class ChatMessage(BaseModel):
    role: str
    content: str
 
class ChatRequest(BaseModel):
    message: str
    session_id: str = "default"  # Add session ID to track different conversations
 
class ChatResponse(BaseModel):
    result: str
    session_id: str
 
router = APIRouter()
 
# In-memory conversation storage (use Redis or database in production)
conversation_sessions: Dict[str, List[Dict[str, Any]]] = {}
 
os.environ["AZURE_OPENAI_ENDPOINT"] = "https://genai-sharedservice-americas.pwc.com"  
os.environ["AZURE_OPENAI_API_KEY"] = "sk-yNb_S9JHvok6NQMFS-u7sQ"  
os.environ["AZURE_OPENAI_API_VERSION"] = "2024-02-15-preview"  
os.environ["AZURE_OPENAI_CHAT_DEPLOYMENT_NAME"] = "azure.gpt-4o"
 
# Create httpx client with SSL verification disabled
http_client = httpx.Client(verify=False)
 
# Initialize Azure OpenAI client with SSL verification disabled
try:
    client = AzureOpenAI(
        api_key=os.environ["AZURE_OPENAI_API_KEY"],
        api_version=os.environ["AZURE_OPENAI_API_VERSION"],
        azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
        timeout=30.0,
        max_retries=2,
        http_client=http_client
    )
    print("✓ Azure OpenAI client initialized successfully (SSL verification disabled)\n")
except Exception as e:
    print(f"✗ Failed to initialize Azure OpenAI client: {str(e)}\n")
    traceback.print_exc()
 
# Define the tool/function schema
tools = [
    {
        "type": "function",
        "function": {
            "name": "get_scan_history",
            "description": "Get scan history with pipeline tracking. Returns information about recent compliance scan pipelines including their status, scan types, and metadata.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_scan_results",
            "description": "Get detailed results of a completed compliance scan by scan ID. Returns comprehensive scan results including compliance score, issues found, and detailed analysis.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "The scan ID to get detailed results for"
                    }
                },
                "required": ["scan_id"]
            }
        }
    }
]
 
async def get_scan_history():
    """Get scan history with pipeline tracking (bonus feature for hackathon)"""
    try:
        # Import here to avoid circular imports
        from services.scan_tracker import ScanTracker
       
        scan_tracker = ScanTracker()
        pipelines = scan_tracker.get_all_pipelines()
       
        # Format scan history with pipeline information
        history = []
        for pipeline in pipelines[:10]:  # Get last 10 pipelines
            history.append({
                "pipeline_id": pipeline.get("pipeline_id", "unknown"),
                "file_id": pipeline.get("file_id", "unknown"),
                "scan_type": pipeline.get("scan_type", "comprehensive"),
                "timestamp": pipeline.get("created_at", "unknown"),
                "status": pipeline.get("status", "unknown"),
                "total_scans": pipeline.get("total_scans", 0),
                "current_scan_id": pipeline.get("current_scan_id"),
                "metadata": pipeline.get("metadata", {})
            })
       
        return {
            "total_pipelines": len(pipelines),
            "pipelines": history,
            "message": "Pipeline-based scan history"
        }
    except Exception as e:
        return {
            "total_pipelines": 0,
            "pipelines": [],
            "error": f"Failed to load scan history: {str(e)}"
        }
 
# async def get_scan_history() -> str:
#     """Get scan history with pipeline tracking (bonus feature for hackathon)"""
   
#     # Hardcoded response for testing
#     result = {
#         "total_pipelines": 3,
#         "pipelines": [
#             {
#                 "pipeline_id": "pipe_001",
#                 "file_id": "file_12345",
#                 "scan_type": "comprehensive",
#                 "timestamp": "2025-10-22T10:30:00",
#                 "status": "completed",
#                 "total_scans": 5,
#                 "current_scan_id": "scan_789",
#                 "metadata": {
#                     "compliance_score": 92,
#                     "critical_issues": 2,
#                     "warnings": 5
#                 }
#             },
#             {
#                 "pipeline_id": "pipe_002",
#                 "file_id": "file_67890",
#                 "scan_type": "quick",
#                 "timestamp": "2025-10-22T09:15:00",
#                 "status": "completed",
#                 "total_scans": 3,
#                 "current_scan_id": "scan_456",
#                 "metadata": {
#                     "compliance_score": 87,
#                     "critical_issues": 0,
#                     "warnings": 8
#                 }
#             },
#             {
#                 "pipeline_id": "pipe_003",
#                 "file_id": "file_11223",
#                 "scan_type": "comprehensive",
#                 "timestamp": "2025-10-22T08:00:00",
#                 "status": "in_progress",
#                 "total_scans": 7,
#                 "current_scan_id": "scan_123",
#                 "metadata": {
#                     "compliance_score": 0,
#                     "critical_issues": 0,
#                     "warnings": 0
#                 }
#             }
#         ],
#         "message": "Pipeline-based scan history"
#     }
   
#     return json.dumps(result, indent=2)
 
 
async def get_scan_results(scan_id: str):
    """
    Get the detailed results of a completed scan
   
    Args:
        scan_id: The scan ID to get results for
   
    Returns:
        Dictionary with detailed scan results
    """
    try:
        scan_service = ScanService()
        results = scan_service.get_scan_results(scan_id)
       
        if not results:
            return {
                "error": f"Scan results not found for scan ID: {scan_id}",
                "scan_id": scan_id,
                "found": False
            }
       
        return {
            "scan_id": scan_id,
            "found": True,
            "results": results
        }
       
    except Exception as e:
        return {
            "error": f"Failed to get scan results: {str(e)}",
            "scan_id": scan_id,
            "found": False
        }
 
def get_session_history(session_id: str) -> List[Dict[str, Any]]:
    """Get conversation history for a session"""
    if session_id not in conversation_sessions:
        # Initialize with enhanced system message for better formatting
        conversation_sessions[session_id] = [
            {
                "role": "system",
                "content": """You are VibeCode Assistant, a helpful AI assistant specialized in compliance scanning and code analysis.
 
CRITICAL FORMATTING REQUIREMENTS:
1. ALWAYS use clear section headers with **Header Name:**
2. Use bullet points (•) for all lists and key information
3. Use numbered lists (1., 2., 3.) for sequential steps or scan results
4. Separate sections with blank lines
5. Format scan IDs, scores, and statistics prominently
6. Use consistent spacing and indentation
 
RESPONSE STRUCTURE EXAMPLES:
 
For scan history:
**📊 Recent Scan History**
 
**Pipeline Overview:**
• Total Pipelines: [number]
• Last Updated: [date]
 
**Scan Details:**
1. **Pipeline ID:** `[id]`
   • **Scan Type:** [type]
   • **Status:** [status]
   • **Timestamp:** [date]
   • **Compliance Score:** [score]%
   • **Issues Found:** [number]
   • **Scan ID:** `[full_scan_id]`
 
2. **Pipeline ID:** `[id]`
   • **Scan Type:** [type]
   • **Status:** [status]
   • **Timestamp:** [date]
   • **Compliance Score:** [score]%
   • **Issues Found:** [number]
   • **Scan ID:** `[full_scan_id]`
 
For scan results:
**🔍 Scan Results for ID: `[scan_id]`**
 
**📋 General Details:**
• **Scan Type:** [type]
• **Timestamp:** [date]
• **Compliance Score:** [score]
• **Total Files Scanned:** [number]
• **Total Issues Found:** [number]
 
**⚠️ Issues Found:**
1. **[Issue Category]:**
   • **Severity:** [level]
   • **Description:** [details]
   • **Files Affected:** [list]
   • **Remediation:** [suggestion]
 
2. **[Issue Category]:**
   • **Severity:** [level]
   • **Description:** [details]
   • **Files Affected:** [list]
   • **Remediation:** [suggestion]
 
**📁 File Details:**
• **Filename:** [name]
• **File Size:** [size]
• **File Path:** [path]
 
CONTEXT:
You help users with:
• Viewing recent compliance scan history and pipeline tracking
• Getting detailed results from completed scans
• Understanding compliance scores and issues
• Analyzing scan metadata and performance
 
ALWAYS follow the exact formatting structure shown above. Use emojis, consistent spacing, and clear section breaks."""
            }
        ]
    return conversation_sessions[session_id]
 
def update_session_history(session_id: str, message: Dict[str, Any]):
    """Add a message to session history"""
    if session_id not in conversation_sessions:
        get_session_history(session_id)  # Initialize if needed
   
    conversation_sessions[session_id].append(message)
   
    # Keep only last 6 messages (system + last 5 messages to maintain context)
    # This ensures we keep system message + last few exchanges
    if len(conversation_sessions[session_id]) > 7:
        system_msg = conversation_sessions[session_id][0]  # Keep system message
        recent_messages = conversation_sessions[session_id][-6:]  # Keep last 6
        conversation_sessions[session_id] = [system_msg] + recent_messages
 
def get_last_three_messages(conversation_history: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Get the last 3 exchanges (system + last 6 messages max)"""
    # Always include system message if it exists
    system_message = None
    user_messages = []
   
    for msg in conversation_history:
        if msg["role"] == "system":
            system_message = msg
        else:
            user_messages.append(msg)
   
    # Get last 6 non-system messages (3 exchanges of user-assistant)
    recent_messages = user_messages[-6:] if len(user_messages) >= 6 else user_messages
   
    # Combine system message with recent messages
    if system_message:
        return [system_message] + recent_messages
    else:
        return recent_messages
 
# Add logging configuration at the top
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
 
@router.post("/chat", response_model=ChatResponse)
async def chat_endpoint(request: ChatRequest):
    """
    Chat endpoint for compliance scan queries.
    Only requires message and session_id. Manages conversation history internally.
    """
    try:
        logger.info(f"Chat request received for session: {request.session_id}")
        logger.info(f"User message: {request.message}")
       
        # Get conversation history for this session
        conversation_history = get_session_history(request.session_id)
       
        # Add the new user message to session history
        user_message = {"role": "user", "content": request.message}
        update_session_history(request.session_id, user_message)
       
        # Get the working conversation (last 3 exchanges + system message)
        working_conversation = get_last_three_messages(conversation_sessions[request.session_id])
       
        logger.info(f"Working conversation length: {len(working_conversation)}")
       
        # Send request to Azure OpenAI with enhanced parameters for better formatting
        response = client.chat.completions.create(
            model=os.environ["AZURE_OPENAI_CHAT_DEPLOYMENT_NAME"],
            messages=working_conversation,
            tools=tools,
            tool_choice="auto",
            temperature=0.3,  # Lower temperature for more consistent formatting
            max_tokens=1500,  # Ensure sufficient tokens for detailed responses
            top_p=0.9
        )
       
        message = response.choices[0].message
        result_content = ""
       
        logger.info(f"Message content: {message.content}")
        logger.info(f"Tool calls detected: {bool(message.tool_calls)}")
       
        if message.tool_calls:
            logger.info(f"Number of tool calls: {len(message.tool_calls)}")
           
            # Handle tool calls - Fix: Handle null content
            tool_call_message = {
                "role": "assistant",
                "content": message.content or "",
                "tool_calls": [
                    {
                        "id": tool_call.id,
                        "type": "function",
                        "function": {
                            "name": tool_call.function.name,
                            "arguments": tool_call.function.arguments
                        }
                    } for tool_call in message.tool_calls
                ]
            }
            working_conversation.append(tool_call_message)
           
            for tool_call in message.tool_calls:
                logger.info(f"Invoking tool: {tool_call.function.name}")
                logger.info(f"Tool arguments: {tool_call.function.arguments}")
               
                if tool_call.function.name == "get_scan_history":
                    # Call the function
                    function_response = await get_scan_history()
                    logger.info(f"get_scan_history response: {function_response}")
                   
                    tool_response = {
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "name": "get_scan_history",
                        "content": json.dumps(function_response)
                    }
                    working_conversation.append(tool_response)
               
                elif tool_call.function.name == "get_scan_results":
                    # Parse arguments and call the function
                    try:
                        arguments = json.loads(tool_call.function.arguments)
                        scan_id = arguments.get("scan_id")
                        logger.info(f"get_scan_results called with scan_id: {scan_id}")
                       
                        function_response = await get_scan_results(scan_id)
                        logger.info(f"get_scan_results response: {function_response}")
                       
                        tool_response = {
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "name": "get_scan_results",
                            "content": json.dumps(function_response)
                        }
                        working_conversation.append(tool_response)
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse tool arguments: {e}")
                        tool_response = {
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "name": "get_scan_results",
                            "content": json.dumps({"error": "Invalid arguments provided"})
                        }
                        working_conversation.append(tool_response)
           
            logger.info(f"Sending second request with {len(working_conversation)} messages")
           
            # Get final response after function execution with formatting emphasis
            second_response = client.chat.completions.create(
                model=os.environ["AZURE_OPENAI_CHAT_DEPLOYMENT_NAME"],
                messages=working_conversation + [
                    {
                        "role": "user",
                        "content": "Please format the response exactly as specified in your system instructions. Use proper headers, bullet points, and spacing. Structure the response clearly with sections separated by blank lines."
                    }
                ],
                tools=tools,
                temperature=0.2,
                max_tokens=2000,
                top_p=0.8
            )
           
            final_message = second_response.choices[0].message
            result_content = final_message.content
            logger.info(f"Final response: {result_content}")
           
            # Add assistant's final response to session history
            assistant_message = {"role": "assistant", "content": result_content}
            update_session_history(request.session_id, assistant_message)
        else:
            # Regular response without tool calls
            result_content = message.content
            logger.info(f"Regular response (no tools): {result_content}")
           
            # Add assistant's response to session history
            assistant_message = {"role": "assistant", "content": result_content}
            update_session_history(request.session_id, assistant_message)
       
        # Post-process the response to ensure good formatting
        formatted_result = format_response(result_content)
       
        return ChatResponse(
            result=formatted_result,
            session_id=request.session_id
        )
       
    except Exception as e:
        logger.error(f"Error in chat endpoint: {type(e).__name__}")
        logger.error(f"Error message: {str(e)}")
        traceback.print_exc()
       
        raise HTTPException(
            status_code=500,
            detail=f"Chat processing failed: {str(e)}"
        )
 
def format_response(content: str) -> str:
    """
    Post-process response content to ensure good formatting
    """
    if not content:
        return "I apologize, but I couldn't generate a proper response. Please try again."
   
    # Ensure proper line breaks and spacing
    lines = content.split('\n')
    formatted_lines = []
   
    for i, line in enumerate(lines):
        line = line.strip()
        if line:
            # Check if this is a section header
            if line.startswith('**') and line.endswith(':**'):
                # Add extra spacing before section headers (except first line)
                if i > 0 and formatted_lines and formatted_lines[-1] != '':
                    formatted_lines.append('')
                formatted_lines.append(line)
            # Check if this is a numbered list item
            elif re.match(r'^\d+\.\s+\*\*.*:\*\*', line):
                # Add spacing before numbered items
                if formatted_lines and formatted_lines[-1] != '':
                    formatted_lines.append('')
                formatted_lines.append(line)
            # Check if this is a bullet point
            elif line.startswith(('• ', '- ', '* ')):
                formatted_lines.append(line)
            # Check if this is a sub-bullet (indented)
            elif line.startswith('   • ') or line.startswith('   - '):
                formatted_lines.append(line)
            # Regular content
            else:
                formatted_lines.append(line)
        else:
            # Preserve empty lines for spacing, but avoid multiple consecutive empty lines
            if formatted_lines and formatted_lines[-1] != '':
                formatted_lines.append('')
   
    result = '\n'.join(formatted_lines)
   
    # Ensure the response isn't empty
    if not result.strip():
        return "I apologize, but I couldn't generate a proper response. Please try again with a more specific question."
   
    return result
 
# Add endpoint to clear conversation history
@router.delete("/chat/{session_id}")
async def clear_conversation(session_id: str):
    """Clear conversation history for a session"""
    if session_id in conversation_sessions:
        del conversation_sessions[session_id]
    return {"message": f"Conversation history cleared for session {session_id}"}
 
# Add endpoint to get conversation history (for debugging)
@router.get("/chat/{session_id}/history")
async def get_conversation_history(session_id: str):
    """Get conversation history for a session (debugging purpose)"""
    history = get_session_history(session_id)
    # Return only user and assistant messages (exclude system and tool messages)
    user_assistant_history = [
        msg for msg in history
        if msg["role"] in ["user", "assistant"]
    ]
    return {"session_id": session_id, "history": user_assistant_history}
 

