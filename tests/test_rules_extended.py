import pytest
from app.services.resolution import ResolutionService
from app.models import Finding
from uuid import uuid4
from unittest.mock import MagicMock

@pytest.fixture
def service(session):
    return ResolutionService(session)

def test_fix_sha224_hash(service):
    finding = Finding(id=uuid4(), title="Sha224 Hash", description="Use of hashlib.sha224 is insecure")
    content = "import hashlib\nh = hashlib.sha224(b'test')"
    fixed = service._generate_fix(finding, None, content=content)
    assert "hashlib.sha256(" in fixed

def test_fix_request_session_timeout(service):
    finding = Finding(id=uuid4(), title="request_without_timeout", description="Missing timeout")
    content = "import requests\nresp = requests.get('https://example.com')"
    fixed = service._generate_fix(finding, None, content=content)
    assert "timeout=10, " in fixed

def test_try_except_pass_rule(service):
    finding = Finding(title="try_except_pass", description="B110: try_except_pass")
    content = "try:\n    do_something()\nexcept:\n    pass"
    fixed = service._generate_fix(finding, None, content=content)
    assert "logging.error" in fixed

def test_sqlalchemy_execute_text_wrap(service):
    # Test conn.execute wrapping
    finding = Finding(title="Sqlalchemy Execute Raw Query", line_number=1)
    content = "conn.execute('SELECT 1')"
    fixed = service._generate_fix(finding, None, content=content)
    assert "text('SELECT 1')" in fixed
    assert "from sqlalchemy import text" in fixed

def test_cwe_89_sql_injection_remediation(service):
    # Test that CWE-89 triggers the correct logic
    finding = Finding(title="CWE-CWE-89: SQL Injection", line_number=1)
    content = "cursor.execute('SELECT * FROM table WHERE id = ' + user_id)"
    fixed = service._generate_fix(finding, None, content=content)
    assert "# [SECURITY] Use parameterized queries" in fixed

def test_sql_false_positive_non_greedy(service):
    # Test complex line with multiple parentheses and already parameterized
    finding = Finding(title="SQL Injection", line_number=1)
    content = "cursor.execute('SELECT * FROM docs WHERE id = ?', (doc_id,)) # some comment"
    fixed = service._generate_fix(finding, None, content=content)
    assert "# nosec B608 - already parameterized" in fixed
    assert fixed.count("# [SECURITY]") == 0

def test_sql_duplicate_prevention_line_specific(service):
    content = "cursor.execute('SELECT 1')\ncursor.execute('SELECT 2')"
    
    # Finding for line 1
    f1 = Finding(title="hardcoded_sql", line_number=1)
    fixed1 = service._generate_fix(f1, None, content=content)
    assert "SELECT 1') # [SECURITY]" in fixed1
    
    # Finding for line 1 again (should not duplicate)
    fixed2 = service._generate_fix(f1, None, content=fixed1)
    assert fixed2 is None # Already has [SECURITY]

def test_fix_django_no_csrf_token(service):
    finding = Finding(id=uuid4(), title="Django No Csrf Token")
    content = "<form method='post'>\n    <input type='text'>\n</form>"
    fixed = service._generate_fix(finding, None, content=content)
    assert "{% csrf_token %}" in fixed

def test_fix_prototype_pollution(service):
    finding = Finding(id=uuid4(), title="Prototype Pollution Loop")
    content = "obj[attr] = value;"
    fixed = service._generate_fix(finding, None, content=content)
    assert "if(attr !== '__proto__'" in fixed
