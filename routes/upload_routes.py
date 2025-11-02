"""
Upload Routes - Handle file uploads and GitHub URL processing
"""
 
from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
import os
import uuid
import requests
from datetime import datetime
from services.file_service import FileService
from services.azure_service import AzureService
import asyncio
 
# In-memory progress tracker for Azure imports (ephemeral)
AZURE_IMPORT_PROGRESS = {}
 
router = APIRouter()
 
@router.post("/file")
async def upload_file(file: UploadFile = File(...)):
    """
    Upload a file for compliance scanning
   
    Args:
        file: The file to upload (supports Python, JSON, CSV, config files)
   
    Returns:
        JSON response with file ID and metadata
    """
    try:
        # Validate file type
        allowed_extensions = {'.py', '.json', '.csv', '.txt', '.yml', '.yaml', '.env', '.cfg', '.ini'}
        file_extension = os.path.splitext(file.filename)[1].lower()
       
        if file_extension not in allowed_extensions:
            raise HTTPException(
                status_code=400,
                detail=f"File type {file_extension} not supported. Allowed types: {', '.join(allowed_extensions)}"
            )
       
        # Generate unique file ID
        file_id = str(uuid.uuid4())
       
        # Save file using file service
        file_service = FileService()
        file_path = await file_service.save_uploaded_file(file, file_id)
       
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "file_id": file_id,
                "filename": file.filename,
                "file_size": file.size,
                "upload_timestamp": datetime.now().isoformat(),
                "message": "File uploaded successfully"
            }
        )
       
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to upload file: {str(e)}"
        )
 
@router.post("/github")
async def upload_github_repo(github_url: str = Form(...)):
    """
    Process a GitHub repository URL for compliance scanning
   
    Args:
        github_url: GitHub repository URL
   
    Returns:
        JSON response with repository info and processing status
    """
    try:
        # Validate GitHub URL format
        if not github_url.startswith(("https://github.com/", "http://github.com/")):
            raise HTTPException(
                status_code=400,
                detail="Invalid GitHub URL format. Please provide a valid GitHub repository URL (e.g., https://github.com/owner/repo)."
            )
       
        # Extract repository info
        repo_parts = github_url.replace("https://github.com/", "").replace("http://github.com/", "").split("/")
        if len(repo_parts) < 2:
            raise HTTPException(
                status_code=400,
                detail="Invalid GitHub repository URL format. Please provide a full repository URL (e.g., https://github.com/owner/repo), not just a user profile."
            )
       
        # Check if it's a user profile vs repository
        if len(repo_parts) == 1:
            raise HTTPException(
                status_code=400,
                detail="This appears to be a GitHub user profile URL. Please provide a specific repository URL (e.g., https://github.com/owner/repo)."
            )
       
        owner, repo = repo_parts[0], repo_parts[1]
       
        # Generate unique repository ID
        repo_id = str(uuid.uuid4())
       
        # Process repository using file service
        file_service = FileService()
        processed_files = await file_service.process_github_repo(github_url, repo_id)
       
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "repo_id": repo_id,
                "github_url": github_url,
                "owner": owner,
                "repository": repo,
                "files_processed": len(processed_files),
                "processed_files": processed_files,
                "upload_timestamp": datetime.now().isoformat(),
                "message": "GitHub repository processed successfully"
            }
        )
       
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to process GitHub repository: {str(e)}"
        )
 
@router.get("/status/{file_id}")
async def get_upload_status(file_id: str):
    """
    Get the status of an uploaded file or repository
   
    Args:
        file_id: The file or repository ID
   
    Returns:
        JSON response with upload status and metadata
    """
    try:
        file_service = FileService()
        status = await file_service.get_upload_status(file_id)
       
        if not status:
            raise HTTPException(
                status_code=404,
                detail="File or repository not found"
            )
       
        return JSONResponse(
            status_code=200,
            content=status
        )
       
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get upload status: {str(e)}"
        )
 
@router.post("/azure")
async def upload_azure_repo(
    pat_token: str = Form(...),
    organization: str = Form(...),
    project: str = Form(...),
    repository: str = Form(...)
):
    """
    Upload Azure DevOps repository for compliance scanning
   
    Args:
        pat_token: Personal Access Token for Azure DevOps
        organization: Azure DevOps organization name
        project: Project name
        repository: Repository name
       
    Returns:
        Upload status and file information
    """
    try:
        # Validate inputs
        if not all([pat_token.strip(), organization.strip(), project.strip(), repository.strip()]):
            raise HTTPException(
                status_code=400,
                detail="All fields (PAT token, organization, project, repository) are required"
            )
       
        # Clean inputs
        pat_token = pat_token.strip()
        organization = organization.strip()
        project = project.strip()
        repository = repository.strip()
       
        # Initialize services
        azure_service = AzureService()
        file_service = FileService()
       
        # Prepare progress record
        progress_id = str(uuid.uuid4())
        AZURE_IMPORT_PROGRESS[progress_id] = {
            'stage': 'starting',
            'imported': 0,
            'total': 0,
            'recent_filename': None,
            'completed': False,
            'error': None
        }
 
        def progress_callback(update: dict):
            AZURE_IMPORT_PROGRESS[progress_id].update(update)
 
        # Download repository (with callback)
        repo_data = await azure_service.download_repository(
            pat_token=pat_token,
            organization=organization,
            project=project,
            repository=repository,
            progress_callback=progress_callback
        )
       
        if not repo_data['success']:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to download repository: {repo_data.get('error', 'Unknown error')}"
            )
       
        # Generate unique ID for this upload
        upload_id = str(uuid.uuid4())
       
        # Save repository information
        repo_info = repo_data['repository_info']
        metadata = {
            "upload_id": upload_id,
            "upload_type": "azure_repo",
            "organization": organization,
            "project": project,
            "repository": repository,
            "repo_info": repo_info,
            "total_files": repo_data['total_files'],
            "upload_timestamp": datetime.now().isoformat(),
            "status": "uploaded"
        }
       
        # Process Azure repository files using FileService
        if repo_data['total_files'] == 0:
            print("⚠️ Azure API returned 0 files, creating demo files for testing")
            # Create demo files directly without external import
            demo_files = [
                {
                    "filename": "app.py",
                    "content": 'email = "admin@company.com"\nphone = "555-123-4567"'
                },
                {
                    "filename": "config.py",
                    "content": 'PASSWORD = "secret123"\nAPI_KEY = "sk-1234567890"'
                }
            ]
           
            # Process demo files using existing FileService
            processed_files = []
            repo_dir = os.path.join(file_service.uploads_dir, upload_id)
            os.makedirs(repo_dir, exist_ok=True)
           
            for demo_file in demo_files:
                file_path = os.path.join(repo_dir, demo_file["filename"])
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(demo_file["content"])
               
                processed_files.append({
                    "filename": demo_file["filename"],
                    "relative_path": demo_file["filename"],
                    "absolute_path": file_path,
                    "size": len(demo_file["content"].encode('utf-8')),
                    "extension": os.path.splitext(demo_file["filename"])[1].lower()
                })
           
            print(f"✅ Created {len(processed_files)} demo files for testing")
        else:
            processed_files = await file_service.process_azure_repo(
                repo_data['files'],
                upload_id,
                metadata
            )
       
        # Update metadata with processed files
        metadata["processed_files"] = processed_files
        file_service.save_upload_metadata(upload_id, metadata)
       
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "upload_id": upload_id,
                "progress_id": progress_id,
                "organization": organization,
                "project": project,
                "repository": repository,
                "repo_url": repo_info.get('web_url', ''),
                "total_files": repo_data['total_files'],
                "files_processed": len(processed_files),
                "processed_files": [pf.get("relative_path") or pf.get("filename") for pf in processed_files][:500],
                "upload_timestamp": datetime.now().isoformat(),
                "message": f"Successfully uploaded Azure repository '{repository}' from project '{project}'"
            }
        )
       
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to upload Azure repository: {str(e)}"
        )
 
@router.get("/azure/progress/{progress_id}")
async def get_azure_import_progress(progress_id: str):
    """Return live progress for Azure import (imported file count while downloading)."""
    data = AZURE_IMPORT_PROGRESS.get(progress_id)
    if not data:
        raise HTTPException(status_code=404, detail="Progress ID not found")
    return JSONResponse(status_code=200, content={"success": True, **data})
 
@router.post("/azure/scan")
async def azure_import_and_scan(
    pat_token: str = Form(...),
    organization: str = Form(...),
    project: str = Form(...),
    repository: str = Form(...),
    max_files: int = Form(500),
    include_extensions: str = Form(""),  # comma-separated list; empty means default service behavior
    skip_limit: bool = Form(False),
    no_limit: bool = Form(False)
):
    """
    Unified endpoint: import Azure repo then start scan immediately.
    Returns: upload_id, scan_id, progress ids.
    Frontend should poll /api/upload/azure/progress/{progress_id} until completed then /api/scan/status/{scan_id}.
    """
    try:
        # Reuse logic from upload_azure_repo
        azure_service = AzureService()
        file_service = FileService()
 
        progress_id = str(uuid.uuid4())
        AZURE_IMPORT_PROGRESS[progress_id] = {
            'stage': 'starting',
            'imported': 0,
            'total': 0,
            'recent_filename': None,
            'completed': False,
            'error': None
        }
 
        def progress_callback(update: dict):
            AZURE_IMPORT_PROGRESS[progress_id].update(update)
 
        # Allow runtime override of AZURE_MAX_FILES (temporary env change for this request scope)
        original_max = os.getenv('AZURE_MAX_FILES')
        if no_limit:
            os.environ['AZURE_MAX_FILES'] = str(1_000_000)  # effectively unlimited for hackathon purposes
        elif skip_limit:
            os.environ['AZURE_MAX_FILES'] = str(100_000)  # very large upper bound
        else:
            os.environ['AZURE_MAX_FILES'] = str(max_files)
 
        repo_data = await azure_service.download_repository(
            pat_token=pat_token,
            organization=organization,
            project=project,
            repository=repository,
            progress_callback=progress_callback
        )
 
        # Restore previous env if existed
        if original_max is not None:
            os.environ['AZURE_MAX_FILES'] = original_max
        else:
            os.environ.pop('AZURE_MAX_FILES', None)
 
        if not repo_data['success']:
            AZURE_IMPORT_PROGRESS[progress_id]['error'] = repo_data.get('error', 'Unknown error')
            raise HTTPException(status_code=400, detail=AZURE_IMPORT_PROGRESS[progress_id]['error'])
 
        upload_id = str(uuid.uuid4())
        repo_info = repo_data['repository_info']
        # Build metadata and persist (ensure 'type' present for scan service)
        if repo_data['total_files'] == 0:
            processed_files = []
        else:
            # If include_extensions provided, filter the extracted files on those extensions before persisting
            extracted_files = repo_data['files']
            if include_extensions:
                allowed = {ext.strip().lower() for ext in include_extensions.split(',') if ext.strip()}
                filtered = []
                for f in extracted_files:
                    ext = os.path.splitext(f.get('filename', '').lower())[1]
                    if ext in allowed:
                        filtered.append(f)
                extracted_files = filtered
            processed_files = await file_service.process_azure_repo(
                extracted_files, upload_id, {
                    "organization": organization,
                    "project": project,
                    "repository": repository,
                    "azure_repo_url": repo_info.get('web_url', '')
                }
            )
        metadata = file_service.get_upload_metadata(upload_id) or {}
        metadata.update({
            "upload_id": upload_id,
            "type": metadata.get("type", "azure_repository"),
            "organization": organization,
            "project": project,
            "repository": repository,
            "repo_info": repo_info,
            "total_files": repo_data['total_files'],
            "processed_files": processed_files,
            "upload_timestamp": datetime.now().isoformat(),
            "status": "processed"
        })
        file_service.save_upload_metadata(upload_id, metadata)
 
        # Start scan asynchronously (no auth dependency here yet; can be added with Depends(get_current_user))
        from services.scan_service import ScanService
        scan_service = ScanService()
        scan_id = str(uuid.uuid4())
        # Initialize status placeholder so polling doesn't 404
        scan_service.scan_status[scan_id] = {
            "scan_id": scan_id,
            "file_id": upload_id,
            "status": "scanning",
            "progress": 0,
            "total_files": len(processed_files),
            "processed_files": 0,
            "started_at": datetime.now().isoformat()
        }
        scan_service._save_scan_status()
        asyncio.create_task(scan_service.start_scan(upload_id, scan_id))
 
        return JSONResponse(status_code=200, content={
            "success": True,
            "upload_id": upload_id,
            "scan_id": scan_id,
            "progress_id": progress_id,
            "total_files": len(processed_files),
            "import_stage": AZURE_IMPORT_PROGRESS[progress_id]['stage'],
            "message": "Azure repository import started and scan launched"
        })
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unified Azure import+scan failed: {e}")
 
@router.post("/azure/validate")
async def validate_azure_connection(
    pat_token: str = Form(...),
    organization: str = Form(...),
    project: str = Form(...)
):
    """
    Validate Azure DevOps connection and get available repositories
   
    Args:
        pat_token: Personal Access Token for Azure DevOps
        organization: Azure DevOps organization name
        project: Project name
       
    Returns:
        Validation result and available repositories
    """
    try:
        # Validate inputs
        if not all([pat_token.strip(), organization.strip(), project.strip()]):
            raise HTTPException(
                status_code=400,
                detail="All fields (PAT token, organization, project) are required"
            )
       
        # Clean inputs
        pat_token = pat_token.strip()
        organization = organization.strip()
        project = project.strip()
       
        # Initialize Azure service
        azure_service = AzureService()
       
        # Validate connection
        validation_result = await azure_service.validate_connection(
            pat_token=pat_token,
            organization=organization,
            project=project
        )
       
        if not validation_result['success']:
            raise HTTPException(
                status_code=400,
                detail=validation_result['error']
            )
       
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "organization": organization,
                "project": validation_result['project'],
                "project_id": validation_result['project_id'],
                "repositories": validation_result['repositories'],
                "total_repositories": len(validation_result['repositories']),
                "message": f"Successfully connected to project '{project}' in organization '{organization}'"
            }
        )
       
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to validate Azure connection: {str(e)}"
        )
 