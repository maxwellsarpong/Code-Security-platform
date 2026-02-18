import pytest
from pathlib import Path
from app.models import Finding
from app.services.resolution import ResolutionService
from uuid import uuid4

def test_rule_django_csrf(session):
    service = ResolutionService(session)
    finding = Finding(
        id=uuid4(),
        title="Django No Csrf Token",
        description="Missing CSRF token in form",
        file_path="templates/login.html"
    )
    content = '<form method="post">\n    <input type="text" name="user">\n</form>'
    
    fixed = service._generate_fix(finding, Path("/tmp"), content=content)
    assert fixed is not None
    assert "{% csrf_token %}" in fixed
    assert '<form method="post">\n    {% csrf_token %}' in fixed

def test_rule_hardcoded_password(session):
    service = ResolutionService(session)
    finding = Finding(
        id=uuid4(),
        title="hardcoded_password_string",
        description="Hardcoded password found",
        file_path="settings.py"
    )
    content = 'DB_PASSWORD = "secret_pass"\nDEBUG = True'
    
    fixed = service._generate_fix(finding, Path("/tmp"), content=content)
    assert fixed is not None
    assert "os.environ.get('PASSWORD', 'REPLACE_ME')" in fixed
    assert "import os" in fixed

def test_rule_insecure_document_write(session):
    service = ResolutionService(session)
    finding = Finding(
        id=uuid4(),
        title="Insecure Document Method",
        description="document.write is insecure",
        file_path="script.js"
    )
    content = 'function alertUser() {\n    document.write("Hello");\n}'
    
    fixed = service._generate_fix(finding, Path("/tmp"), content=content)
    assert fixed is not None
    assert "console.log(" in fixed
    assert "document.write" not in fixed or "// [FIXED]" in fixed
