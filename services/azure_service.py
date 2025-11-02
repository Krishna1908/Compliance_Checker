import os
import requests
import zipfile
import tempfile
import json
import concurrent.futures
from typing import Dict, List, Optional
from datetime import datetime
 
class AzureService:
    def __init__(self):
        self.base_url = "https://dev.azure.com"
        self.api_version = "7.1-preview.1"
        # Force SSL verification off for simplicity (user request)
        # NOTE: This is insecure for production. Re-enable later for secure deployments.
        self.verify_ssl = False
 
    def _request(self, url: str, headers: Dict, timeout: int = 90) -> requests.Response:
        return requests.get(url, headers=headers, timeout=timeout, verify=False)
   
    async def download_repository(self, pat_token: str, organization: str, project: str, repository: str, progress_callback=None) -> Dict:
        """
        Download Azure DevOps repository using PAT token
       
        Args:
            pat_token: Personal Access Token for Azure DevOps
            organization: Azure DevOps organization name
            project: Project name
            repository: Repository name
           
        Returns:
            Dictionary with downloaded files information
        """
        try:
            # Validate inputs
            if not all([pat_token, organization, project, repository]):
                raise ValueError("All parameters (pat_token, organization, project, repository) are required")
           
            # Create headers with PAT authentication
            headers = {
                'Authorization': f'Basic {self._encode_pat_token(pat_token)}',
                'Content-Type': 'application/json'
            }
           
            # Get repository information
            repo_info = await self._get_repository_info(organization, project, repository, headers)
           
            # Get repository items (files) directly instead of ZIP download
            # First, get the default branch
            refs_url = f"{self.base_url}/{organization}/{project}/_apis/git/repositories/{repository}/refs?api-version={self.api_version}"
            refs_response = self._request(refs_url, headers)
            refs_response.raise_for_status()
           
            refs_data = refs_response.json()
            default_branch = "main"  # Default fallback
           
            # Find the default branch (usually main or master)
            for ref in refs_data.get('value', []):
                ref_name = ref.get('name', '')
                if ref_name in ['refs/heads/main', 'refs/heads/master', 'refs/heads/develop']:
                    default_branch = ref_name.replace('refs/heads/', '')
                    break
           
            print(f"Using branch: {default_branch}")
           
            # Get repository items (without content first) for speed
            items_url = f"{self.base_url}/{organization}/{project}/_apis/git/repositories/{repository}/items?recursionLevel=Full&versionType=branch&version={default_branch}&api-version={self.api_version}"
            items_response = self._request(items_url, headers)
            items_response.raise_for_status()
            items_data = items_response.json()
            all_items = items_data.get('value', [])
            print(f"Found {len(all_items)} items in repository (pre-filter)")
 
            # Filter scannable files
            scannable = []
            scannable_before_limit = []
            for item in all_items:
                if item.get('isFolder', False):
                    continue
                path = item.get('path', '').lstrip('/')
                if self._should_scan_file(path):
                    scannable.append(item)
                    scannable_before_limit.append(item)
            print(f"Scannable files: {len(scannable)}")
 
            # Apply limit for performance
            max_files = int(os.getenv('AZURE_MAX_FILES', '500'))
            limit_applied = 0
            if len(scannable) > max_files:
                print(f"Limiting files from {len(scannable)} to {max_files} for performance")
                limit_applied = len(scannable) - max_files
                scannable = scannable[:max_files]
 
            extracted_files: List[Dict] = []
 
            # Initial progress callback (listing done)
            if progress_callback:
                try:
                    progress_callback({
                        'stage': 'importing',
                        'imported': 0,
                        'total': len(scannable),
                        'recent_filename': None,
                        'completed': False
                    })
                except Exception as _e:
                    print(f"progress_callback initial error: {_e}")
 
            def fetch_content(item):
                path = item.get('path', '')
                filename = path.lstrip('/')
                content_url = f"{self.base_url}/{organization}/{project}/_apis/git/repositories/{repository}/items?path={path}&includeContent=true&api-version={self.api_version}"
                try:
                    content_response = requests.get(content_url, headers=headers, timeout=60, verify=False)
                    content_response.raise_for_status()
                    # Azure items API sometimes returns raw text (not JSON) for file content when includeContent=true.
                    file_content = ''
                    encoding = None
                    # Try JSON first, fallback to raw text
                    try:
                        data = content_response.json()
                        file_content = data.get('content', '')
                        encoding = data.get('contentMetadata', {}).get('encoding')
                        if encoding == 'base64':
                            import base64
                            file_content = base64.b64decode(file_content).decode('utf-8', errors='ignore')
                    except ValueError:
                        # Not JSON; treat body as text
                        file_content = content_response.text
                    except Exception as parse_e:
                        print(f"Parse error for {filename}: {parse_e}; using raw text fallback")
                        file_content = content_response.text
                    # Defensive: ensure string
                    if not isinstance(file_content, str):
                        try:
                            file_content = str(file_content)
                        except Exception:
                            file_content = ''
                    return {
                        'filename': filename,
                        'content': file_content,
                        'size': item.get('size', 0),
                        'modified_time': item.get('latestCommit', {}).get('committer', {}).get('date', ''),
                        'error': None
                    }
                except Exception as e:
                    print(f"Error retrieving file {filename}: {e}")
                    return {
                        'filename': filename,
                        'content': '',
                        'size': item.get('size', 0),
                        'modified_time': '',
                        'error': str(e)
                    }
 
            # Concurrent fetch
            workers = min(12, max(4, os.cpu_count() or 4))
            print(f"Fetching contents concurrently with {workers} workers")
            success_count = 0
            failure_count = 0
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                futures = [executor.submit(fetch_content, item) for item in scannable]
                for i, future in enumerate(concurrent.futures.as_completed(futures), start=1):
                    result = future.result()
                    if result:
                        extracted_files.append(result)
                        if result.get('error'):
                            failure_count += 1
                        else:
                            success_count += 1
                        if progress_callback:
                            try:
                                progress_callback({
                                    'stage': 'importing',
                                    'imported': len(extracted_files),
                                    'total': len(scannable),
                                    'recent_filename': result.get('filename'),
                                    'completed': False
                                })
                            except Exception as _e:
                                print(f"progress_callback mid error: {_e}")
                    if i % 50 == 0:
                        print(f"Fetched {i}/{len(scannable)} files...")
 
            print(f"Successfully processed {len(extracted_files)} files (success: {success_count}, failures: {failure_count})")
 
            # Final progress callback
            if progress_callback:
                try:
                    progress_callback({
                        'stage': 'importing',
                        'imported': len(extracted_files),
                        'total': len(scannable),
                        'recent_filename': None,
                        'completed': True
                    })
                except Exception as _e:
                    print(f"progress_callback final error: {_e}")
           
            return {
                'success': True,
                'repository_info': repo_info,
                'files': extracted_files,
                'total_files': len(extracted_files),
                'branch_used': default_branch,
                'download_timestamp': datetime.now().isoformat(),
                'raw_items_count': len(all_items),
                'scannable_count_before_limit': len(scannable_before_limit),
                'scannable_count_after_limit': len(scannable),
                'limit_applied': limit_applied,
                'success_count': success_count,
                'failure_count': failure_count,
                'max_files': max_files
            }
           
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code
            body = e.response.text
            if status == 401:
                raise Exception("Invalid PAT token or insufficient permissions. Ensure PAT includes 'Code (Read)' and 'Project and Team (Read)'.")
            elif status == 403:
                raise Exception("Access forbidden: PAT lacks required scope or repo permissions. Add 'Code (Read)' scope or verify repository visibility.")
            elif status == 404:
                raise Exception(f"Repository '{repository}' not found in project '{project}'. Verify names are exact (case-sensitive).")
            else:
                raise Exception(f"Azure DevOps API error {status}: {body[:300]}")
        except Exception as e:
            raise Exception(f"Failed to download Azure repository: {str(e)}")
   
    async def _get_repository_info(self, organization: str, project: str, repository: str, headers: Dict) -> Dict:
        """
        Get repository information from Azure DevOps
       
        Args:
            organization: Azure DevOps organization name
            project: Project name
            repository: Repository name
            headers: HTTP headers with authentication
           
        Returns:
            Repository information dictionary
        """
        try:
            repo_url = f"{self.base_url}/{organization}/{project}/_apis/git/repositories/{repository}?api-version={self.api_version}"
            response = self._request(repo_url, headers)
            response.raise_for_status()
           
            repo_data = response.json()
           
            return {
                'id': repo_data.get('id'),
                'name': repo_data.get('name'),
                'url': repo_data.get('url'),
                'project': repo_data.get('project', {}).get('name'),
                'organization': organization,
                'default_branch': repo_data.get('defaultBranch', 'main'),
                'size': repo_data.get('size', 0),
                'web_url': repo_data.get('webUrl')
            }
           
        except Exception as e:
            raise Exception(f"Failed to get repository info: {str(e)}")
   
    def _encode_pat_token(self, pat_token: str) -> str:
        """
        Encode PAT token for Basic authentication
       
        Args:
            pat_token: Personal Access Token
           
        Returns:
            Base64 encoded token for Basic auth
        """
        import base64
        # Azure DevOps PAT tokens use empty username and PAT as password
        credentials = f":{pat_token}"
        encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        return encoded_credentials
   
    def _should_scan_file(self, filename: str) -> bool:
        """
        Determine if a file should be scanned for compliance
       
        Args:
            filename: Name of the file
           
        Returns:
            True if file should be scanned, False otherwise
        """
        # Skip binary files and common non-code files (more permissive for demo)
        skip_extensions = {
            '.exe', '.dll', '.so', '.dylib', '.bin', '.obj', '.o', '.a', '.lib',
            '.zip', '.tar', '.gz', '.rar', '.7z', '.bz2', '.xz',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.svg', '.ico',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv',
            '.woff', '.woff2', '.ttf', '.eot', '.otf',
            '.pyc', '.pyo', '.pyd', '.class', '.jar', '.war'
        }
       
        # Get file extension
        file_ext = os.path.splitext(filename.lower())[1]
       
        # Skip if extension is in skip list
        if file_ext in skip_extensions:
            print(f"  Skipping {filename} - extension {file_ext} in skip list")
            return False
       
        # Skip common non-code files
        skip_filenames = {
            'package-lock.json', 'yarn.lock', 'composer.lock',
            'thumbs.db', '.ds_store', 'desktop.ini'
        }
       
        filename_lower = filename.lower()
        if any(skip_name in filename_lower for skip_name in skip_filenames):
            print(f"  Skipping {filename} - filename in skip list")
            return False
       
        # Skip files in common non-code directories
        skip_dirs = {
            'node_modules', '.git', '.svn', '.hg', 'vendor',
            'build', 'dist', 'target', 'bin', 'obj',
            '.vs', '.idea', '.vscode', '__pycache__'
        }
       
        if any(f'/{skip_dir}/' in filename_lower or f'\\{skip_dir}\\' in filename_lower for skip_dir in skip_dirs):
            print(f"  Skipping {filename} - in skip directory")
            return False
       
        # Include common code file extensions
        code_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.c', '.cpp', '.cs',
            '.php', '.rb', '.go', '.rs', '.swift', '.kt', '.scala', '.clj',
            '.html', '.css', '.scss', '.sass', '.less', '.xml', '.json', '.yaml', '.yml',
            '.sql', '.sh', '.bash', '.ps1', '.bat', '.cmd',
            '.md', '.txt', '.cfg', '.conf', '.ini', '.env', '.properties',
            '.dockerfile', '.dockerignore', '.gitignore', '.gitattributes'
        }
       
        # Include if it's a code file or has no extension (might be important config)
        result = file_ext in code_extensions or file_ext == ''
        if result:
            print(f"  ✅ File {filename} will be scanned")
        else:
            print(f"  Skipping {filename} - not a code file (ext: {file_ext})")
        return result
   
    async def validate_connection(self, pat_token: str, organization: str, project: str) -> Dict:
        """
        Validate Azure DevOps connection and permissions
       
        Args:
            pat_token: Personal Access Token
            organization: Azure DevOps organization name
            project: Project name
           
        Returns:
            Validation result dictionary
        """
        try:
            headers = {
                'Authorization': f'Basic {self._encode_pat_token(pat_token)}',
                'Content-Type': 'application/json'
            }
           
            # Test connection by getting project info
            project_url = f"{self.base_url}/{organization}/_apis/projects/{project}?api-version={self.api_version}"
            response = self._request(project_url, headers)
            response.raise_for_status()
           
            project_data = response.json()
           
            # Get repositories in the project
            repos_url = f"{self.base_url}/{organization}/{project}/_apis/git/repositories?api-version={self.api_version}"
            repos_response = self._request(repos_url, headers)
            repos_response.raise_for_status()
           
            repos_data = repos_response.json()
            repositories = [repo['name'] for repo in repos_data.get('value', [])]
           
            return {
                'success': True,
                'organization': organization,
                'project': project_data.get('name'),
                'project_id': project_data.get('id'),
                'repositories': repositories,
                'permissions': 'valid'
            }
           
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code
            if status == 401:
                return {
                    'success': False,
                    'error': "Invalid PAT token or insufficient permissions. Re-create PAT with scopes: 'Code (Read)', 'Project and Team (Read)'.",
                    'permissions': 'invalid'
                }
            elif status == 403:
                return {
                    'success': False,
                    'error': "Forbidden: PAT missing 'Code (Read)' or repository access restricted (private repo without permission).",
                    'permissions': 'forbidden'
                }
            elif status == 404:
                return {
                    'success': False,
                    'error': f'Project "{project}" not found in organization "{organization}". Check spelling and that PAT has org access.',
                    'permissions': 'not_found'
                }
            else:
                return {
                    'success': False,
                    'error': f'Azure DevOps API error: {status}',
                    'permissions': 'error'
                }
        except Exception as e:
            return {
                'success': False,
                'error': f'Connection validation failed: {str(e)}',
                'permissions': 'error'
            }
 