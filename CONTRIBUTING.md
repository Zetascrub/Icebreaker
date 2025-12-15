# Contributing to Icebreaker

Thank you for your interest in contributing to Icebreaker! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Coding Standards](#coding-standards)
- [Adding New Features](#adding-new-features)

## Code of Conduct

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Respect differing viewpoints and experiences

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Icebreaker
   cd Icebreaker
   ```

3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/Zetascrub/Icebreaker
   ```

## Development Setup

### Prerequisites

- Python 3.11+
- Git
- nmap (optional, for faster scanning)

### Installation

```bash
# Create virtual environment
python3.11 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install in development mode with dev dependencies
pip install -e ".[dev]"

# Initialize database
python -c "from icebreaker.db.database import engine; from icebreaker.db.models import Base; Base.metadata.create_all(bind=engine)"
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=icebreaker --cov-report=html

# Run specific test file
pytest tests/test_analyzers.py

# Run tests matching pattern
pytest -k test_http_basic
```

### Running Linter

```bash
# Check code
ruff check icebreaker tests

# Auto-fix issues
ruff check --fix icebreaker tests

# Format code
ruff format icebreaker tests
```

## Making Changes

### 1. Create a Branch

```bash
# Update your fork
git fetch upstream
git checkout main
git merge upstream/main

# Create feature branch
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-123
```

### 2. Make Your Changes

- Write clear, concise code
- Follow existing code style
- Add tests for new functionality
- Update documentation as needed

### 3. Commit Your Changes

```bash
# Stage changes
git add .

# Commit with descriptive message
git commit -m "Add XSS scanner analyzer

- Implements reflected XSS detection
- Adds tests for common XSS payloads
- Updates documentation"
```

**Commit Message Format:**
```
<type>: <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Test additions/changes
- `refactor`: Code refactoring
- `style`: Formatting changes
- `chore`: Maintenance tasks

**Example:**
```
feat: Add SQL injection scanner

Implements error-based SQL injection detection for common databases.
Includes payload generation and response analysis.

Closes #42
```

## Testing

### Writing Tests

All new features should include tests. Place tests in the `tests/` directory.

**Example Test:**
```python
# tests/test_my_analyzer.py
import pytest
from icebreaker.analyzers.my_analyzer import MyAnalyzer
from icebreaker.core.models import Service, RunContext

@pytest.mark.asyncio
async def test_my_analyzer_detects_vulnerability():
    analyzer = MyAnalyzer()
    ctx = RunContext.new(preset="test", out_dir="/tmp/test")
    service = Service(target="example.com", port=80, name="http")

    findings = await analyzer.run(ctx, service)

    assert len(findings) > 0
    assert findings[0].severity == "HIGH"
```

### Test Coverage

- Aim for **50%+ coverage** minimum
- **80%+ coverage** for core modules
- Test both success and failure paths
- Include edge cases

### Running Integration Tests

```bash
# Start test server
docker-compose -f docker-compose.test.yml up -d

# Run integration tests
pytest tests/integration/

# Stop test server
docker-compose -f docker-compose.test.yml down
```

## Submitting Changes

### 1. Push to Your Fork

```bash
git push origin feature/your-feature-name
```

### 2. Create Pull Request

1. Go to https://github.com/Zetascrub/Icebreaker
2. Click "New Pull Request"
3. Select your fork and branch
4. Fill in PR template:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Tests added/updated
- [ ] All tests passing
- [ ] Manual testing performed

## Checklist
- [ ] Code follows project style
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No new warnings
```

### 3. Code Review

- Address reviewer comments
- Push updates to same branch
- Be responsive and professional

### 4. Merge

Once approved, maintainers will merge your PR.

## Coding Standards

### Python Style

- **PEP 8** compliance
- **Type hints** for all functions
- **Docstrings** for modules, classes, and functions
- **Max line length:** 100 characters

**Example:**
```python
from __future__ import annotations
from typing import List, Optional

async def analyze_target(
    target: str,
    port: int,
    timeout: float = 5.0
) -> List[Finding]:
    """
    Analyze a target for vulnerabilities.

    Args:
        target: Target hostname or IP
        port: Port number to scan
        timeout: Request timeout in seconds

    Returns:
        List of findings discovered

    Raises:
        ValueError: If target is invalid
    """
    if not target:
        raise ValueError("Target cannot be empty")

    # Analysis logic here
    findings = []
    return findings
```

### Naming Conventions

- **Classes:** `PascalCase`
- **Functions/Methods:** `snake_case`
- **Constants:** `UPPER_SNAKE_CASE`
- **Private members:** `_leading_underscore`

### Import Order

1. Standard library
2. Third-party packages
3. Local imports

```python
from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import httpx
from pydantic import BaseModel

from icebreaker.core.models import Finding
from icebreaker.engine.orchestrator import Orchestrator
```

### Async/Await

- Use `async`/`await` for I/O operations
- Don't block the event loop
- Use `asyncio.gather()` for parallelism

```python
# Good
async def fetch_multiple(urls: List[str]) -> List[Response]:
    tasks = [httpx.get(url) for url in urls]
    return await asyncio.gather(*tasks)

# Bad
async def fetch_multiple(urls: List[str]) -> List[Response]:
    results = []
    for url in urls:
        result = await httpx.get(url)  # Sequential, slow
        results.append(result)
    return results
```

## Adding New Features

### Adding an Analyzer

1. **Create analyzer file:**
   ```bash
   touch icebreaker/analyzers/my_analyzer.py
   ```

2. **Implement analyzer:**
   ```python
   from __future__ import annotations
   from typing import List
   from icebreaker.core.models import RunContext, Service, Finding

   class MyAnalyzer:
       """Brief description of what this analyzer does."""

       id = "my_analyzer"
       consumes = ["service:http", "service:https"]

       async def run(
           self,
           ctx: RunContext,
           service: Service
       ) -> List[Finding]:
           """Analyze service for vulnerabilities."""
           findings = []

           # Your analysis logic here
           if detected_vulnerability:
               findings.append(Finding(
                   id=f"{service.target}:{service.port}:my_vuln",
                   title="Vulnerability Title",
                   severity="HIGH",
                   target=service.target,
                   port=service.port,
                   tags=["web", "security"],
                   details={"info": "Additional details"},
                   confidence=0.9,
               ))

           return findings
   ```

3. **Add to CLI** (`cli.py`):
   ```python
   from icebreaker.analyzers.my_analyzer import MyAnalyzer

   analyzers = [
       # ... existing analyzers
       MyAnalyzer(),
   ]
   ```

4. **Write tests:**
   ```python
   # tests/test_my_analyzer.py
   import pytest
   from icebreaker.analyzers.my_analyzer import MyAnalyzer

   @pytest.mark.asyncio
   async def test_my_analyzer():
       analyzer = MyAnalyzer()
       # Test logic here
   ```

5. **Update documentation:**
   - Add to README.md feature list
   - Document in appropriate guides

### Adding a Writer

Similar pattern, but implement `write()` method instead of `run()`.

### Adding an API Endpoint

1. **Add to appropriate router** (e.g., `api/routers/scans.py`)
2. **Add Pydantic models** for request/response
3. **Write integration test**
4. **Update API documentation**

## Project Structure

```
Icebreaker/
├── icebreaker/
│   ├── analyzers/        # Vulnerability analyzers
│   ├── api/              # FastAPI application
│   │   └── routers/      # API endpoints
│   ├── core/             # Core models and utilities
│   ├── db/               # Database models
│   ├── detectors/        # Port scanners
│   ├── engine/           # Orchestration logic
│   ├── importers/        # Data importers
│   ├── plugins/          # Plugin system
│   ├── reports/          # Report generation
│   ├── scheduler/        # Scheduled scans
│   ├── web/              # Web UI templates/static
│   └── writers/          # Export formats
├── tests/                # Test suite
├── docs/                 # Documentation
└── .github/              # CI/CD workflows
```

## Common Tasks

### Adding a New Dependency

```bash
# Add to pyproject.toml under [project.dependencies]
pip install new-package
pip freeze | grep new-package  # Get exact version
# Add: "new-package>=X.Y.Z"
```

### Updating Documentation

- **README.md** - User-facing features
- **docs/ARCHITECTURE.md** - System design
- **docs/DEPLOYMENT.md** - Deployment guides
- **Docstrings** - Code-level documentation

### Running Development Server

```bash
# Web UI
uvicorn icebreaker.api.app:app --reload --port 8000

# CLI
icebreaker -t scope.txt
```

## Getting Help

- **GitHub Issues:** Report bugs or request features
- **Discussions:** Ask questions or share ideas
- **Pull Requests:** Get feedback on your code

## Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Mentioned in release notes
- Credited in commits

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to Icebreaker! 🎉
