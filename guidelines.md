==========================
CODE REVIEW GUIDELINES
==========================

Purpose:
--------
To ensure code quality, maintainability, security, performance, readability, and adherence to team standards.

General Principles:
-------------------
- Code must be readable, understandable, and self-explanatory.
- Follow the principle of least surprise.
- Prefer clarity over cleverness.
- Changes must be necessary and minimal in scope.

1. Code Style & Formatting:
---------------------------
- Follow project-specific style guide (e.g., PEP8, Google Java Style Guide).
- Ensure proper indentation and spacing.
- Limit line length (usually 80 or 120 characters).
- Remove commented-out code unless necessary.
- Use meaningful and consistent naming conventions (camelCase, snake_case, etc.).

2. Documentation & Comments:
----------------------------
- Public functions/classes should have docstrings.
- Inline comments should explain "why", not "what" (which the code already shows).
- Avoid redundant comments.
- Update outdated comments.

3. Code Structure:
------------------
- Maintain single responsibility per function or class.
- Avoid deeply nested conditionals; refactor for readability.
- Keep functions short and focused.
- Ensure logical grouping of related functions and classes.

4. Testing:
----------
- Include or update unit tests for all new/modified functionality.
- Use descriptive test names.
- Tests should be deterministic and isolated.
- Cover edge cases and boundary values.
- Prefer mocks/stubs for external services.

5. Error Handling & Logging:
----------------------------
- Handle exceptions gracefully and specifically.
- Do not use bare `except:` clauses.
- Log appropriate warnings/errors, but avoid excessive logging.
- Do not expose sensitive data in logs or error messages.

6. Security:
------------
- Validate and sanitize all inputs (e.g., from user, files, network).
- Avoid hardcoding secrets or credentials.
- Ensure secure usage of cryptographic functions.
- Use parameterized queries to prevent SQL injection.
- Avoid using insecure dependencies; update outdated packages.

7. Performance:
---------------
- Avoid unnecessary computations or database calls.
- Use appropriate data structures.
- Consider lazy loading, pagination, and batching where applicable.
- Benchmark critical paths when performance matters.

8. Dependencies:
----------------
- Remove unused imports/libraries.
- Ensure third-party libraries are necessary and well-maintained.
- Lock dependency versions when possible (e.g., requirements.txt, package-lock.json).

9. Git & PR Hygiene:
--------------------
- Keep commits clean, meaningful, and scoped.
- Squash or rebase if there are noisy or fixup commits.
- PR title and description should be clear and include context.
- Reference related issues/tickets in the PR description.

10. Language/Framework Specific:
-------------------------------
- Python: Use list comprehensions where appropriate, avoid global variables.
- Java: Use interfaces where needed, prefer immutability.
- JavaScript/TypeScript: Avoid `var`, prefer `const` and `let`; use async/await instead of `.then()` chaining.
- React: Use functional components and hooks; avoid unnecessary re-renders.
- Spring Boot: Use constructor injection, proper layering (Controller → Service → Repository).
- Node.js: Avoid blocking calls; handle async errors using try/catch with async/await.

11. Infrastructure as Code (IaC):
---------------------------------
- Avoid hardcoding secrets; use secure parameters or environment variables.
- Validate and lint templates/scripts (e.g., Terraform, CloudFormation).
- Ensure idempotency of scripts.
- Keep infrastructure code DRY and modular.

12. CI/CD & Automation:
-----------------------
- Ensure all tests pass before merging.
- Validate code coverage thresholds.
- Include relevant linter/static analysis tools in CI pipeline.

13. UX & Accessibility (Frontend-specific):
-------------------------------------------
- Validate layout and responsiveness.
- Ensure keyboard navigability.
- Use semantic HTML where applicable.
- Provide alt text for images and aria labels for dynamic elements.

14. AI/ML Code (If applicable):
-------------------------------
- Ensure model versioning and reproducibility.
- Validate data preprocessing steps.
- Avoid data leakage in training code.
- Document model evaluation metrics and assumptions.

Final Checklist Before Approving:
---------------------------------
- [ ] Code compiles/builds successfully.
- [ ] All tests pass and test coverage is acceptable.
- [ ] Code follows style and readability standards.
- [ ] No unnecessary changes or commented code left.
- [ ] Changes are minimal, scoped, and well-justified.
- [ ] Code is reviewed with a security-first mindset.
- [ ] Documentation (code + PR) is sufficient and clear.

Reviewed by: [Your Name / Bot]
Date: [Auto-filled]