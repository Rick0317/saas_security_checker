"""
Password Strength Checker
Comprehensive password policy and strength analysis
"""

import logging
import re
from datetime import datetime
from typing import Dict, List, Optional

class PasswordStrengthChecker:
    """Password strength and policy analysis"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
    def run_test(self, target_url: str, target_domain: str) -> Dict:
        """Run password strength analysis"""
        self.logger.info(f"Starting password strength analysis for {target_url}")
        
        results = {
            'status': 'completed',
            'timestamp': datetime.now().isoformat(),
            'target': target_url,
            'password_policy': {},
            'strength_tests': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # Analyze password policy
            results['password_policy'] = self._analyze_password_policy(target_url)
            
            # Test password strength
            results['strength_tests'] = self._test_password_strength()
            
            # Check for common password vulnerabilities
            self._check_password_vulnerabilities(results)
            
            # Generate recommendations
            self._generate_password_recommendations(results)
            
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
            self.logger.error(f"Error during password strength analysis: {str(e)}")
        
        return results
    
    def _analyze_password_policy(self, target_url: str) -> Dict:
        """Analyze password policy from registration/reset forms"""
        policy = {
            'min_length': None,
            'max_length': None,
            'requires_uppercase': False,
            'requires_lowercase': False,
            'requires_numbers': False,
            'requires_special_chars': False,
            'common_patterns': [],
            'weak_passwords_accepted': []
        }
        
        try:
            import requests
            from bs4 import BeautifulSoup
            from urllib.parse import urljoin
            
            # Check registration and password reset pages
            test_urls = [
                urljoin(target_url, '/register'),
                urljoin(target_url, '/signup'),
                urljoin(target_url, '/password/reset'),
                urljoin(target_url, '/change-password')
            ]
            
            for test_url in test_urls:
                try:
                    response = requests.get(test_url, timeout=10)
                    if response.status_code == 200:
                        soup = BeautifulSoup(response.content, 'html.parser')
                        
                        # Look for password policy hints
                        policy_text = soup.get_text().lower()
                        
                        # Check for length requirements
                        length_patterns = [
                            r'minimum\s+(\d+)\s+characters',
                            r'at\s+least\s+(\d+)\s+characters',
                            r'(\d+)\s+characters\s+minimum',
                            r'min\s+(\d+)',
                            r'length\s+(\d+)'
                        ]
                        
                        for pattern in length_patterns:
                            match = re.search(pattern, policy_text)
                            if match:
                                policy['min_length'] = int(match.group(1))
                                break
                        
                        # Check for character requirements
                        if 'uppercase' in policy_text or 'capital' in policy_text:
                            policy['requires_uppercase'] = True
                        
                        if 'lowercase' in policy_text or 'small' in policy_text:
                            policy['requires_lowercase'] = True
                        
                        if 'number' in policy_text or 'digit' in policy_text:
                            policy['requires_numbers'] = True
                        
                        if 'special' in policy_text or 'symbol' in policy_text:
                            policy['requires_special_chars'] = True
                        
                        # Look for password input attributes
                        password_inputs = soup.find_all('input', {'type': 'password'})
                        for pwd_input in password_inputs:
                            minlength = pwd_input.get('minlength')
                            if minlength:
                                policy['min_length'] = int(minlength)
                            
                            maxlength = pwd_input.get('maxlength')
                            if maxlength:
                                policy['max_length'] = int(maxlength)
                            
                            pattern = pwd_input.get('pattern')
                            if pattern:
                                policy['common_patterns'].append(pattern)
                
                except Exception as e:
                    self.logger.debug(f"Error analyzing password policy at {test_url}: {str(e)}")
        
        except Exception as e:
            policy['error'] = str(e)
        
        return policy
    
    def _test_password_strength(self) -> Dict:
        """Test various password strengths"""
        test_results = {
            'weak_passwords': [],
            'medium_passwords': [],
            'strong_passwords': [],
            'common_passwords': []
        }
        
        # Test passwords of different strengths
        test_passwords = [
            # Weak passwords
            '123456', 'password', '123456789', '12345678', '12345',
            'qwerty', 'abc123', 'password123', 'admin', 'letmein',
            
            # Medium passwords
            'Password1', 'MyPassword123', 'SecurePass1', 'Test123!',
            'MySecure123', 'Password2023', 'Secure2023!',
            
            # Strong passwords
            'MyStr0ng!P@ssw0rd', 'S3cur3P@ssw0rd!', 'C0mpl3x!P@ss2023',
            'V3ryS3cur3!P@ss', 'UltraS3cur3!P@ssw0rd2023',
            
            # Common patterns
            'January2023', 'Password123!', 'Welcome123', 'ChangeMe123',
            'TempPassword1', 'NewPassword123', 'DefaultPass1'
        ]
        
        for password in test_passwords:
            strength = self._calculate_password_strength(password)
            
            if strength['score'] < 3:
                test_results['weak_passwords'].append({
                    'password': password,
                    'strength': strength
                })
            elif strength['score'] < 6:
                test_results['medium_passwords'].append({
                    'password': password,
                    'strength': strength
                })
            else:
                test_results['strong_passwords'].append({
                    'password': password,
                    'strength': strength
                })
            
            # Check if it's a common password
            if self._is_common_password(password):
                test_results['common_passwords'].append({
                    'password': password,
                    'reason': 'Common password pattern'
                })
        
        return test_results
    
    def _calculate_password_strength(self, password: str) -> Dict:
        """Calculate password strength score"""
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 8:
            score += 1
        else:
            feedback.append('Password too short (minimum 8 characters)')
        
        if len(password) >= 12:
            score += 1
        else:
            feedback.append('Consider using 12+ characters')
        
        # Character variety checks
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append('Add lowercase letters')
        
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append('Add uppercase letters')
        
        if re.search(r'[0-9]', password):
            score += 1
        else:
            feedback.append('Add numbers')
        
        if re.search(r'[^a-zA-Z0-9]', password):
            score += 1
        else:
            feedback.append('Add special characters')
        
        # Pattern checks
        if not re.search(r'(.)\1{2,}', password):  # No repeated characters
            score += 1
        else:
            feedback.append('Avoid repeated characters')
        
        if not re.search(r'(012|123|234|345|456|567|678|789|890)', password):  # No sequential numbers
            score += 1
        else:
            feedback.append('Avoid sequential numbers')
        
        if not re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):  # No sequential letters
            score += 1
        else:
            feedback.append('Avoid sequential letters')
        
        # Common word check
        common_words = ['password', 'admin', 'user', 'login', 'welcome', 'change', 'default', 'temp', 'test']
        if not any(word in password.lower() for word in common_words):
            score += 1
        else:
            feedback.append('Avoid common words')
        
        # Determine strength level
        if score < 3:
            strength_level = 'Very Weak'
        elif score < 5:
            strength_level = 'Weak'
        elif score < 7:
            strength_level = 'Medium'
        elif score < 9:
            strength_level = 'Strong'
        else:
            strength_level = 'Very Strong'
        
        return {
            'score': score,
            'level': strength_level,
            'feedback': feedback,
            'length': len(password)
        }
    
    def _is_common_password(self, password: str) -> bool:
        """Check if password is commonly used"""
        # Common password patterns
        common_patterns = [
            r'^\d+$',  # All numbers
            r'^[a-zA-Z]+$',  # All letters
            r'^password\d*$',  # Password with numbers
            r'^admin\d*$',  # Admin with numbers
            r'^user\d*$',  # User with numbers
            r'^\d{4,8}$',  # Short number sequences
            r'^[a-zA-Z]{4,8}$',  # Short letter sequences
            r'^[a-zA-Z]+\d+$',  # Letters followed by numbers
            r'^\d+[a-zA-Z]+$',  # Numbers followed by letters
        ]
        
        for pattern in common_patterns:
            if re.match(pattern, password, re.IGNORECASE):
                return True
        
        # Check against common password list
        common_passwords = [
            '123456', 'password', '123456789', '12345678', '12345',
            'qwerty', 'abc123', 'password123', 'admin', 'letmein',
            'welcome', 'monkey', '1234567890', 'dragon', 'master',
            'hello', 'freedom', 'whatever', 'qazwsx', 'trustno1'
        ]
        
        return password.lower() in common_passwords
    
    def _check_password_vulnerabilities(self, results: Dict):
        """Check for password-related vulnerabilities"""
        vulnerabilities = []
        
        policy = results.get('password_policy', {})
        
        # Check for weak password policy
        if policy.get('min_length', 0) < 8:
            vulnerabilities.append({
                'type': 'Weak Password Policy',
                'severity': 'High',
                'description': f'Minimum password length is {policy.get("min_length", "not set")} (should be 8+)',
                'recommendation': 'Increase minimum password length to 8+ characters'
            })
        
        if not policy.get('requires_uppercase', False):
            vulnerabilities.append({
                'type': 'Weak Password Policy',
                'severity': 'Medium',
                'description': 'Password policy does not require uppercase letters',
                'recommendation': 'Require uppercase letters in passwords'
            })
        
        if not policy.get('requires_numbers', False):
            vulnerabilities.append({
                'type': 'Weak Password Policy',
                'severity': 'Medium',
                'description': 'Password policy does not require numbers',
                'recommendation': 'Require numbers in passwords'
            })
        
        if not policy.get('requires_special_chars', False):
            vulnerabilities.append({
                'type': 'Weak Password Policy',
                'severity': 'Medium',
                'description': 'Password policy does not require special characters',
                'recommendation': 'Require special characters in passwords'
            })
        
        # Check for common password patterns
        strength_tests = results.get('strength_tests', {})
        common_passwords = strength_tests.get('common_passwords', [])
        
        if len(common_passwords) > 0:
            vulnerabilities.append({
                'type': 'Common Password Patterns',
                'severity': 'Medium',
                'description': f'Found {len(common_passwords)} common password patterns',
                'recommendation': 'Implement password blacklist for common patterns'
            })
        
        # Check for weak passwords in test results
        weak_passwords = strength_tests.get('weak_passwords', [])
        if len(weak_passwords) > 5:
            vulnerabilities.append({
                'type': 'Weak Password Acceptance',
                'severity': 'High',
                'description': f'System accepts {len(weak_passwords)} weak passwords',
                'recommendation': 'Implement stronger password validation'
            })
        
        results['vulnerabilities'].extend(vulnerabilities)
    
    def _generate_password_recommendations(self, results: Dict):
        """Generate password security recommendations"""
        recommendations = []
        
        policy = results.get('password_policy', {})
        
        # Policy recommendations
        if not policy.get('min_length') or policy['min_length'] < 8:
            recommendations.append({
                'priority': 'High',
                'recommendation': 'Implement minimum password length',
                'details': 'Set minimum password length to at least 8 characters'
            })
        
        if not policy.get('requires_uppercase', False):
            recommendations.append({
                'priority': 'High',
                'recommendation': 'Require character variety',
                'details': 'Require uppercase letters, lowercase letters, numbers, and special characters'
            })
        
        # Strength recommendations
        strength_tests = results.get('strength_tests', {})
        weak_count = len(strength_tests.get('weak_passwords', []))
        
        if weak_count > 0:
            recommendations.append({
                'priority': 'High',
                'recommendation': 'Implement password strength validation',
                'details': f'Reject weak passwords (found {weak_count} weak patterns)'
            })
        
        # General recommendations
        recommendations.extend([
            {
                'priority': 'High',
                'recommendation': 'Implement password blacklist',
                'details': 'Maintain a blacklist of common and compromised passwords'
            },
            {
                'priority': 'Medium',
                'recommendation': 'Implement password history',
                'details': 'Prevent reuse of recent passwords'
            },
            {
                'priority': 'Medium',
                'recommendation': 'Implement password expiration',
                'details': 'Require periodic password changes (90-180 days)'
            },
            {
                'priority': 'Low',
                'recommendation': 'Implement password hints',
                'details': 'Provide real-time password strength feedback to users'
            },
            {
                'priority': 'Low',
                'recommendation': 'Consider password managers',
                'details': 'Encourage users to use password managers for strong passwords'
            }
        ])
        
        results['recommendations'].extend(recommendations)
    
    def check_password_policy_compliance(self, password: str, policy: Dict) -> Dict:
        """Check if a password complies with the given policy"""
        compliance = {
            'compliant': True,
            'violations': [],
            'score': 0
        }
        
        # Check minimum length
        min_length = policy.get('min_length', 0)
        if len(password) < min_length:
            compliance['compliant'] = False
            compliance['violations'].append(f'Password too short (minimum {min_length} characters)')
        else:
            compliance['score'] += 1
        
        # Check maximum length
        max_length = policy.get('max_length')
        if max_length and len(password) > max_length:
            compliance['compliant'] = False
            compliance['violations'].append(f'Password too long (maximum {max_length} characters)')
        
        # Check character requirements
        if policy.get('requires_uppercase', False):
            if not re.search(r'[A-Z]', password):
                compliance['compliant'] = False
                compliance['violations'].append('Password must contain uppercase letters')
            else:
                compliance['score'] += 1
        
        if policy.get('requires_lowercase', False):
            if not re.search(r'[a-z]', password):
                compliance['compliant'] = False
                compliance['violations'].append('Password must contain lowercase letters')
            else:
                compliance['score'] += 1
        
        if policy.get('requires_numbers', False):
            if not re.search(r'[0-9]', password):
                compliance['compliant'] = False
                compliance['violations'].append('Password must contain numbers')
            else:
                compliance['score'] += 1
        
        if policy.get('requires_special_chars', False):
            if not re.search(r'[^a-zA-Z0-9]', password):
                compliance['compliant'] = False
                compliance['violations'].append('Password must contain special characters')
            else:
                compliance['score'] += 1
        
        # Check against patterns
        for pattern in policy.get('common_patterns', []):
            if re.search(pattern, password):
                compliance['compliant'] = False
                compliance['violations'].append(f'Password matches forbidden pattern: {pattern}')
        
        return compliance
