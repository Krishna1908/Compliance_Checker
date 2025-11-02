"""
File Service - Handle file operations and GitHub repository processing
"""
 
import os
import shutil
import requests
import zipfile
import tempfile
from datetime import datetime
from typing import List, Dict, Optional
import json
 
class FileService:
    def __init__(self):
        self.uploads_dir = "uploads"
        self.reports_dir = "reports"
        self.metadata_file = "uploads/metadata.json"
        self.ensure_directories()
        self._upload_metadata = self._load_metadata()
   
    def ensure_directories(self):
        """Ensure required directories exist"""
        os.makedirs(self.uploads_dir, exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)
   
    def _load_metadata(self) -> Dict:
        """Load metadata from file"""
        try:
            if os.path.exists(self.metadata_file):
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            print(f"Error loading metadata: {e}")
            return {}
   
    def _save_metadata(self):
        """Save metadata to file"""
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self._upload_metadata, f, indent=2)
        except Exception as e:
            print(f"Error saving metadata: {e}")
   
    def save_upload_metadata(self, file_id: str, metadata: Dict):
        """
        Save upload metadata for a file or repository
       
        Args:
            file_id: Unique identifier for the file/repository
            metadata: Metadata dictionary to save
        """
        self._upload_metadata[file_id] = metadata
        self._save_metadata()
 
    def get_upload_metadata(self, file_id: str) -> Optional[Dict]:
        """Return raw metadata dictionary for given upload id."""
        return self._upload_metadata.get(file_id)
   
    async def save_uploaded_file(self, file, file_id: str) -> str:
        """
        Save an uploaded file to the uploads directory
       
        Args:
            file: FastAPI UploadFile object
            file_id: Unique identifier for the file
       
        Returns:
            Path to the saved file
        """
        try:
            # Create file path
            file_extension = os.path.splitext(file.filename)[1]
            file_path = os.path.join(self.uploads_dir, f"{file_id}{file_extension}")
           
            # Save file content
            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
           
            # Store metadata
            self._upload_metadata[file_id] = {
                "type": "file",
                "filename": file.filename,
                "file_path": file_path,
                "size": file.size,
                "uploaded_at": datetime.now().isoformat(),
                "status": "uploaded"
            }
            self._save_metadata()
           
            return file_path
           
        except Exception as e:
            raise Exception(f"Failed to save uploaded file: {str(e)}")
   
    async def process_github_repo(self, github_url: str, repo_id: str) -> List[Dict]:
        """
        Process a GitHub repository by downloading and extracting files
       
        Args:
            github_url: GitHub repository URL
            repo_id: Unique identifier for the repository
       
        Returns:
            List of processed file information
        """
        try:
            # Extract repository info
            repo_parts = github_url.replace("https://github.com/", "").replace("http://github.com/", "").split("/")
           
            # Validate URL format
            if len(repo_parts) < 2:
                raise ValueError(f"Invalid GitHub repository URL format. Expected: https://github.com/owner/repo, got: {github_url}")
           
            owner, repo = repo_parts[0], repo_parts[1]
           
            # Validate owner and repo names
            if not owner or not repo:
                raise ValueError(f"Invalid owner or repository name. Owner: '{owner}', Repo: '{repo}'")
           
            # Create repository directory
            repo_dir = os.path.join(self.uploads_dir, repo_id)
            os.makedirs(repo_dir, exist_ok=True)
           
            # Download repository as ZIP
            zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/main.zip"
           
            # Handle potential branch names
            try:
                response = requests.get(zip_url, timeout=30, verify=False)  # SSL verification disabled
                if response.status_code != 200:
                    # Try with master branch
                    zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/master.zip"
                    response = requests.get(zip_url, timeout=30, verify=False)  # SSL verification disabled
                   
                if response.status_code != 200:
                    raise Exception(f"Failed to download repository: HTTP {response.status_code}")
                   
            except requests.RequestException as e:
                raise Exception(f"Failed to download repository: {str(e)}")
           
            # Save and extract ZIP
            zip_path = os.path.join(repo_dir, "repository.zip")
            with open(zip_path, "wb") as f:
                f.write(response.content)
           
            # Extract ZIP
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(repo_dir)
           
            # Remove ZIP file
            os.remove(zip_path)
           
            # Find extracted directory and process files
            extracted_dir = None
            for item in os.listdir(repo_dir):
                item_path = os.path.join(repo_dir, item)
                if os.path.isdir(item_path):
                    extracted_dir = item_path
                    break
           
            if not extracted_dir:
                raise Exception("No extracted directory found")
           
            # Process files in the repository
            processed_files = []
            allowed_extensions = {'.py', '.json', '.csv', '.txt', '.yml', '.yaml', '.env', '.cfg', '.ini', '.md'}
           
            for root, dirs, files in os.walk(extracted_dir):
                # Skip certain directories
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__']]
               
                for file in files:
                    file_path = os.path.join(root, file)
                    file_extension = os.path.splitext(file)[1].lower()
                   
                    if file_extension in allowed_extensions:
                        # Calculate relative path
                        relative_path = os.path.relpath(file_path, extracted_dir)
                       
                        processed_files.append({
                            "filename": file,
                            "relative_path": relative_path,
                            "absolute_path": file_path,
                            "size": os.path.getsize(file_path),
                            "extension": file_extension
                        })
           
            # Store metadata
            self._upload_metadata[repo_id] = {
                "type": "repository",
                "github_url": github_url,
                "owner": owner,
                "repository": repo,
                "repo_dir": repo_dir,
                "extracted_dir": extracted_dir,
                "files_count": len(processed_files),
                "processed_files": processed_files,
                "uploaded_at": datetime.now().isoformat(),
                "status": "processed"
            }
            self._save_metadata()
           
            return processed_files
           
        except Exception as e:
            raise Exception(f"Failed to process GitHub repository: {str(e)}")
   
    async def process_azure_repo(self, azure_files: List[Dict], repo_id: str, metadata: Dict) -> List[Dict]:
        """
        Process an Azure DevOps repository files
       
        Args:
            azure_files: List of files from Azure repository
            repo_id: Unique identifier for the repository
            metadata: Azure repository metadata
       
        Returns:
            List of processed file information
        """
        try:
            # Create repository directory
            repo_dir = os.path.join(self.uploads_dir, repo_id)
            os.makedirs(repo_dir, exist_ok=True)
           
            # Process files from Azure
            processed_files = []
           
            for file_data in azure_files:
                filename = file_data.get('filename', 'unknown')
                content = file_data.get('content', '')
                error_flag = file_data.get('error')
               
                # Save file to repository directory
                file_path = os.path.join(repo_dir, filename)
               
                # Create subdirectories if needed
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
               
                # Write file content
                # Write content even if empty so the file presence is reflected; if binary or error, content may be empty.
                try:
                    with open(file_path, 'w', encoding='utf-8', errors='ignore') as f:
                        f.write(content)
                except Exception as write_e:
                    # Fallback: create placeholder file
                    with open(file_path, 'w', encoding='utf-8', errors='ignore') as f:
                        f.write(f"/* extraction_error: {write_e} */")
               
                # Calculate relative path
                relative_path = os.path.relpath(file_path, repo_dir)
               
                processed_files.append({
                    "filename": filename,
                    "relative_path": relative_path,
                    "absolute_path": file_path,
                    "size": len(content.encode('utf-8')),
                    "extension": os.path.splitext(filename)[1].lower(),
                    "ingest_error": error_flag
                })
           
            # Store metadata
            self._upload_metadata[repo_id] = {
                "type": "azure_repository",
                "azure_repo_url": metadata.get("azure_repo_url", ""),
                "organization": metadata.get("organization", ""),
                "project": metadata.get("project", ""),
                "repository": metadata.get("repository", ""),
                "repo_dir": repo_dir,
                "files_count": len(processed_files),
                "processed_files": processed_files,
                "uploaded_at": datetime.now().isoformat(),
                "status": "processed"
            }
            self._save_metadata()
           
            return processed_files
           
        except Exception as e:
            raise Exception(f"Failed to process Azure repository: {str(e)}")
   
    async def get_upload_status(self, file_id: str) -> Optional[Dict]:
        """
        Get the status of an uploaded file or repository
       
        Args:
            file_id: The file or repository ID
       
        Returns:
            Upload status and metadata
        """
        return self._upload_metadata.get(file_id)
   
    async def read_file_content(self, file_path: str) -> str:
        """
        Read the content of a file
       
        Args:
            file_path: Path to the file
       
        Returns:
            File content as string
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            raise Exception(f"Failed to read file {file_path}: {str(e)}")
   
    async def get_file_info(self, file_id: str) -> Optional[Dict]:
        """
        Get detailed information about an uploaded file or repository
       
        Args:
            file_id: The file or repository ID
       
        Returns:
            File information dictionary
        """
        metadata = self._upload_metadata.get(file_id)
        if not metadata:
            return None
       
        if metadata["type"] == "file":
            return {
                "id": file_id,
                "type": "file",
                "filename": metadata["filename"],
                "size": metadata["size"],
                "uploaded_at": metadata["uploaded_at"],
                "status": metadata["status"]
            }
        else:  # repository
            return {
                "id": file_id,
                "type": "repository",
                "github_url": metadata["github_url"],
                "owner": metadata["owner"],
                "repository": metadata["repository"],
                "files_count": metadata["files_count"],
                "uploaded_at": metadata["uploaded_at"],
                "status": metadata["status"]
            }
   
    def cleanup_old_files(self, max_age_hours: int = 24):
        """
        Clean up old uploaded files (for demo purposes)
       
        Args:
            max_age_hours: Maximum age in hours before cleanup
        """
        try:
            current_time = datetime.now()
            files_to_remove = []
           
            for file_id, metadata in self._upload_metadata.items():
                uploaded_at = datetime.fromisoformat(metadata["uploaded_at"])
                age_hours = (current_time - uploaded_at).total_seconds() / 3600
               
                if age_hours > max_age_hours:
                    files_to_remove.append(file_id)
           
            for file_id in files_to_remove:
                metadata = self.upload_metadata[file_id]
               
                if metadata["type"] == "file":
                    # Remove single file
                    if os.path.exists(metadata["file_path"]):
                        os.remove(metadata["file_path"])
                else:
                    # Remove repository directory
                    if os.path.exists(metadata["repo_dir"]):
                        shutil.rmtree(metadata["repo_dir"])
               
                del self._upload_metadata[file_id]
               
        except Exception as e:
            print(f"Error during cleanup: {str(e)}")