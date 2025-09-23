"""
Dependency and Supply Chain Security Checker
Checks for vulnerable dependencies and supply chain security issues
"""

import json
import logging
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import requests

class DependencyChecker:
    """Dependency and supply chain security analysis"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
    def run_test(self, target_url: str, target_domain: str) -> Dict:
        """Run dependency and supply chain security checks"""
        self.logger.info(f"Starting dependency security checks for {target_url}")
        
        results = {
            'status': 'completed',
            'timestamp': datetime.now().isoformat(),
            'target': target_url,
            'dependencies': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # Check for common dependency files
            dependency_files = self._find_dependency_files(target_url)
            results['dependency_files'] = dependency_files
            
            # Analyze each dependency file
            for dep_file in dependency_files:
                dep_results = self._analyze_dependency_file(dep_file, target_url)
                results['dependencies'][dep_file['type']] = dep_results
            
            # Check for supply chain issues
            results['supply_chain'] = self._check_supply_chain_security(target_url)
            
            # Generate recommendations
            self._generate_dependency_recommendations(results)
            
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
            self.logger.error(f"Error during dependency checks: {str(e)}")
        
        return results
    
    def _find_dependency_files(self, target_url: str) -> List[Dict]:
        """Find dependency files in the web application"""
        dependency_files = []
        
        # Common dependency file patterns
        dependency_patterns = [
            {'type': 'npm', 'files': ['package.json', 'package-lock.json', 'yarn.lock']},
            {'type': 'python', 'files': ['requirements.txt', 'Pipfile', 'Pipfile.lock', 'poetry.lock']},
            {'type': 'composer', 'files': ['composer.json', 'composer.lock']},
            {'type': 'maven', 'files': ['pom.xml']},
            {'type': 'gradle', 'files': ['build.gradle', 'build.gradle.kts']},
            {'type': 'gem', 'files': ['Gemfile', 'Gemfile.lock']},
            {'type': 'cargo', 'files': ['Cargo.toml', 'Cargo.lock']},
            {'type': 'go', 'files': ['go.mod', 'go.sum']}
        ]
        
        for pattern in dependency_patterns:
            for file_name in pattern['files']:
                try:
                    file_url = f"{target_url.rstrip('/')}/{file_name}"
                    response = requests.get(file_url, timeout=10)
                    
                    if response.status_code == 200:
                        dependency_files.append({
                            'type': pattern['type'],
                            'file': file_name,
                            'url': file_url,
                            'content': response.text,
                            'size': len(response.content)
                        })
                        
                except Exception as e:
                    self.logger.debug(f"Error checking {file_name}: {str(e)}")
        
        return dependency_files
    
    def _analyze_dependency_file(self, dep_file: Dict, target_url: str) -> Dict:
        """Analyze a specific dependency file"""
        dep_type = dep_file['type']
        content = dep_file['content']
        
        analysis = {
            'file': dep_file['file'],
            'dependencies': [],
            'vulnerabilities': [],
            'outdated_packages': []
        }
        
        try:
            if dep_type == 'npm':
                analysis = self._analyze_npm_dependencies(content)
            elif dep_type == 'python':
                analysis = self._analyze_python_dependencies(content)
            elif dep_type == 'composer':
                analysis = self._analyze_composer_dependencies(content)
            elif dep_type == 'maven':
                analysis = self._analyze_maven_dependencies(content)
            elif dep_type == 'gradle':
                analysis = self._analyze_gradle_dependencies(content)
            elif dep_type == 'gem':
                analysis = self._analyze_gem_dependencies(content)
            elif dep_type == 'cargo':
                analysis = self._analyze_cargo_dependencies(content)
            elif dep_type == 'go':
                analysis = self._analyze_go_dependencies(content)
            
        except Exception as e:
            analysis['error'] = str(e)
            self.logger.error(f"Error analyzing {dep_type} dependencies: {str(e)}")
        
        return analysis
    
    def _analyze_npm_dependencies(self, content: str) -> Dict:
        """Analyze npm package.json dependencies"""
        analysis = {
            'file': 'package.json',
            'dependencies': [],
            'vulnerabilities': [],
            'outdated_packages': []
        }
        
        try:
            package_data = json.loads(content)
            
            # Extract dependencies
            all_deps = {}
            all_deps.update(package_data.get('dependencies', {}))
            all_deps.update(package_data.get('devDependencies', {}))
            all_deps.update(package_data.get('peerDependencies', {}))
            
            for package_name, version in all_deps.items():
                analysis['dependencies'].append({
                    'name': package_name,
                    'version': version,
                    'type': 'npm'
                })
            
            # Check for known vulnerable packages
            vulnerable_packages = self._check_npm_vulnerabilities(list(all_deps.keys()))
            analysis['vulnerabilities'] = vulnerable_packages
            
        except json.JSONDecodeError as e:
            analysis['error'] = f"Invalid JSON: {str(e)}"
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _analyze_python_dependencies(self, content: str) -> Dict:
        """Analyze Python requirements.txt dependencies"""
        analysis = {
            'file': 'requirements.txt',
            'dependencies': [],
            'vulnerabilities': [],
            'outdated_packages': []
        }
        
        try:
            lines = content.strip().split('\n')
            packages = []
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Parse package specification
                    if '==' in line:
                        name, version = line.split('==', 1)
                    elif '>=' in line:
                        name, version = line.split('>=', 1)
                    elif '<=' in line:
                        name, version = line.split('<=', 1)
                    elif '>' in line:
                        name, version = line.split('>', 1)
                    elif '<' in line:
                        name, version = line.split('<', 1)
                    else:
                        name, version = line, 'latest'
                    
                    packages.append(name.strip())
                    analysis['dependencies'].append({
                        'name': name.strip(),
                        'version': version.strip(),
                        'type': 'python'
                    })
            
            # Check for known vulnerable packages
            vulnerable_packages = self._check_python_vulnerabilities(packages)
            analysis['vulnerabilities'] = vulnerable_packages
            
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _analyze_composer_dependencies(self, content: str) -> Dict:
        """Analyze Composer dependencies"""
        analysis = {
            'file': 'composer.json',
            'dependencies': [],
            'vulnerabilities': [],
            'outdated_packages': []
        }
        
        try:
            composer_data = json.loads(content)
            
            # Extract dependencies
            all_deps = {}
            all_deps.update(composer_data.get('require', {}))
            all_deps.update(composer_data.get('require-dev', {}))
            
            for package_name, version in all_deps.items():
                analysis['dependencies'].append({
                    'name': package_name,
                    'version': version,
                    'type': 'composer'
                })
            
        except json.JSONDecodeError as e:
            analysis['error'] = f"Invalid JSON: {str(e)}"
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _analyze_maven_dependencies(self, content: str) -> Dict:
        """Analyze Maven dependencies"""
        analysis = {
            'file': 'pom.xml',
            'dependencies': [],
            'vulnerabilities': [],
            'outdated_packages': []
        }
        
        try:
            # Simple XML parsing for Maven dependencies
            # This is a basic implementation - in production, use proper XML parser
            import re
            
            dependency_pattern = r'<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>.*?</dependency>'
            dependencies = re.findall(dependency_pattern, content, re.DOTALL)
            
            for group_id, artifact_id, version in dependencies:
                package_name = f"{group_id}:{artifact_id}"
                analysis['dependencies'].append({
                    'name': package_name,
                    'version': version.strip(),
                    'type': 'maven'
                })
            
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _analyze_gradle_dependencies(self, content: str) -> Dict:
        """Analyze Gradle dependencies"""
        analysis = {
            'file': 'build.gradle',
            'dependencies': [],
            'vulnerabilities': [],
            'outdated_packages': []
        }
        
        try:
            # Simple parsing for Gradle dependencies
            lines = content.split('\n')
            in_dependencies = False
            
            for line in lines:
                line = line.strip()
                if 'dependencies' in line:
                    in_dependencies = True
                    continue
                elif in_dependencies and line.startswith('}'):
                    break
                elif in_dependencies and ('implementation' in line or 'compile' in line):
                    # Extract dependency information
                    if "'" in line:
                        parts = line.split("'")
                        if len(parts) >= 2:
                            package_name = parts[1]
                            analysis['dependencies'].append({
                                'name': package_name,
                                'version': 'unknown',
                                'type': 'gradle'
                            })
            
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _analyze_gem_dependencies(self, content: str) -> Dict:
        """Analyze Ruby Gem dependencies"""
        analysis = {
            'file': 'Gemfile',
            'dependencies': [],
            'vulnerabilities': [],
            'outdated_packages': []
        }
        
        try:
            lines = content.split('\n')
            
            for line in lines:
                line = line.strip()
                if line.startswith('gem '):
                    # Extract gem name and version
                    parts = line.split(',')
                    gem_name = parts[0].replace('gem ', '').strip().strip("'\"")
                    
                    version = 'latest'
                    if len(parts) > 1:
                        version_part = parts[1].strip()
                        if '~>' in version_part:
                            version = version_part.replace('~>', '').strip().strip("'\"")
                        elif '>=' in version_part:
                            version = version_part.replace('>=', '').strip().strip("'\"")
                    
                    analysis['dependencies'].append({
                        'name': gem_name,
                        'version': version,
                        'type': 'gem'
                    })
            
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _analyze_cargo_dependencies(self, content: str) -> Dict:
        """Analyze Rust Cargo dependencies"""
        analysis = {
            'file': 'Cargo.toml',
            'dependencies': [],
            'vulnerabilities': [],
            'outdated_packages': []
        }
        
        try:
            lines = content.split('\n')
            in_dependencies = False
            
            for line in lines:
                line = line.strip()
                if line == '[dependencies]':
                    in_dependencies = True
                    continue
                elif line.startswith('[') and in_dependencies:
                    break
                elif in_dependencies and '=' in line:
                    package_name = line.split('=')[0].strip()
                    version = line.split('=')[1].strip().strip('"')
                    
                    analysis['dependencies'].append({
                        'name': package_name,
                        'version': version,
                        'type': 'cargo'
                    })
            
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _analyze_go_dependencies(self, content: str) -> Dict:
        """Analyze Go module dependencies"""
        analysis = {
            'file': 'go.mod',
            'dependencies': [],
            'vulnerabilities': [],
            'outdated_packages': []
        }
        
        try:
            lines = content.split('\n')
            
            for line in lines:
                line = line.strip()
                if line.startswith('require ') and '(' in line:
                    # Multi-line require block
                    continue
                elif line.startswith('require ') and not line.endswith('('):
                    # Single line require
                    parts = line.split()
                    if len(parts) >= 3:
                        package_name = parts[1]
                        version = parts[2]
                        
                        analysis['dependencies'].append({
                            'name': package_name,
                            'version': version,
                            'type': 'go'
                        })
                elif not line.startswith('require') and not line.startswith('module') and not line.startswith('go ') and line:
                    # Dependency in multi-line block
                    parts = line.split()
                    if len(parts) >= 2:
                        package_name = parts[0]
                        version = parts[1]
                        
                        analysis['dependencies'].append({
                            'name': package_name,
                            'version': version,
                            'type': 'go'
                        })
            
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _check_npm_vulnerabilities(self, packages: List[str]) -> List[Dict]:
        """Check for npm package vulnerabilities"""
        vulnerabilities = []
        
        # Known vulnerable npm packages (simplified list)
        vulnerable_npm_packages = {
            'lodash': 'Versions < 4.17.21 have prototype pollution vulnerability',
            'moment': 'Versions < 2.29.2 have ReDoS vulnerability',
            'axios': 'Versions < 0.21.1 have SSRF vulnerability',
            'jquery': 'Versions < 3.5.0 have XSS vulnerability',
            'express': 'Versions < 4.17.1 have prototype pollution vulnerability'
        }
        
        for package in packages:
            if package in vulnerable_npm_packages:
                vulnerabilities.append({
                    'type': 'Vulnerable Dependency',
                    'severity': 'High',
                    'package': package,
                    'description': vulnerable_npm_packages[package],
                    'recommendation': f'Update {package} to latest version'
                })
        
        return vulnerabilities
    
    def _check_python_vulnerabilities(self, packages: List[str]) -> List[Dict]:
        """Check for Python package vulnerabilities"""
        vulnerabilities = []
        
        # Known vulnerable Python packages (simplified list)
        vulnerable_python_packages = {
            'django': 'Versions < 3.2.4 have security vulnerabilities',
            'flask': 'Versions < 2.0.1 have security vulnerabilities',
            'requests': 'Versions < 2.25.1 have security vulnerabilities',
            'urllib3': 'Versions < 1.26.5 have security vulnerabilities',
            'pillow': 'Versions < 8.2.0 have security vulnerabilities'
        }
        
        for package in packages:
            if package.lower() in vulnerable_python_packages:
                vulnerabilities.append({
                    'type': 'Vulnerable Dependency',
                    'severity': 'High',
                    'package': package,
                    'description': vulnerable_python_packages[package.lower()],
                    'recommendation': f'Update {package} to latest version'
                })
        
        return vulnerabilities
    
    def _check_supply_chain_security(self, target_url: str) -> Dict:
        """Check for supply chain security issues"""
        supply_chain_results = {
            'cdn_usage': [],
            'external_resources': [],
            'vulnerabilities': []
        }
        
        try:
            response = requests.get(target_url, timeout=30)
            if response.status_code == 200:
                content = response.text
                
                # Check for CDN usage
                cdn_patterns = [
                    'cdnjs.cloudflare.com',
                    'ajax.googleapis.com',
                    'unpkg.com',
                    'jsdelivr.net',
                    'cdn.jsdelivr.net'
                ]
                
                for cdn in cdn_patterns:
                    if cdn in content:
                        supply_chain_results['cdn_usage'].append({
                            'cdn': cdn,
                            'description': f'Using external CDN: {cdn}'
                        })
                
                # Check for external resources
                external_patterns = [
                    'http://', 'https://'
                ]
                
                import re
                for pattern in external_patterns:
                    matches = re.findall(f'{pattern}[^"\'>\s]+', content)
                    for match in matches:
                        if not target_url.split('//')[1].split('/')[0] in match:
                            supply_chain_results['external_resources'].append({
                                'url': match,
                                'description': 'External resource loaded'
                            })
                
                # Check for supply chain vulnerabilities
                if supply_chain_results['cdn_usage']:
                    supply_chain_results['vulnerabilities'].append({
                        'type': 'CDN Dependency',
                        'severity': 'Medium',
                        'description': 'Application depends on external CDNs',
                        'recommendation': 'Consider hosting resources locally or use SRI (Subresource Integrity)'
                    })
                
                if len(supply_chain_results['external_resources']) > 10:
                    supply_chain_results['vulnerabilities'].append({
                        'type': 'External Dependencies',
                        'severity': 'Medium',
                        'description': f'Application loads {len(supply_chain_results["external_resources"])} external resources',
                        'recommendation': 'Review external dependencies and implement SRI'
                    })
        
        except Exception as e:
            supply_chain_results['error'] = str(e)
        
        return supply_chain_results
    
    def _generate_dependency_recommendations(self, results: Dict):
        """Generate dependency security recommendations"""
        recommendations = []
        
        # Count vulnerabilities across all dependency types
        total_vulnerabilities = 0
        for dep_type, dep_results in results.get('dependencies', {}).items():
            vulnerabilities = dep_results.get('vulnerabilities', [])
            total_vulnerabilities += len(vulnerabilities)
        
        if total_vulnerabilities > 0:
            recommendations.append({
                'priority': 'High',
                'recommendation': 'Update vulnerable dependencies',
                'details': f'Found {total_vulnerabilities} vulnerable dependencies across all package managers'
            })
        
        # Check for dependency files exposure
        dependency_files = results.get('dependency_files', [])
        if dependency_files:
            recommendations.append({
                'priority': 'Medium',
                'recommendation': 'Secure dependency files',
                'details': f'Dependency files are accessible: {", ".join([f["file"] for f in dependency_files])}'
            })
        
        # Supply chain recommendations
        supply_chain = results.get('supply_chain', {})
        if supply_chain.get('cdn_usage'):
            recommendations.append({
                'priority': 'Medium',
                'recommendation': 'Implement Subresource Integrity (SRI)',
                'details': 'Add SRI hashes to external resources for integrity verification'
            })
        
        # General recommendations
        recommendations.extend([
            {
                'priority': 'High',
                'recommendation': 'Implement dependency scanning',
                'details': 'Set up automated dependency vulnerability scanning in CI/CD pipeline'
            },
            {
                'priority': 'Medium',
                'recommendation': 'Use dependency pinning',
                'details': 'Pin dependency versions to specific commits or hashes'
            },
            {
                'priority': 'Low',
                'recommendation': 'Regular dependency updates',
                'details': 'Establish regular schedule for dependency updates and security patches'
            }
        ])
        
        results['recommendations'].extend(recommendations)

