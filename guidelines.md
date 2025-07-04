# Code Review Guidelines

## Security
- Validate all user inputs
- Sanitize database queries
- Avoid hardcoded secrets
- Use parameterized SQL queries
- Implement proper authz checks

## Performance
- Avoid N+1 queries
- Use pagination for large datasets
- Cache expensive operations
- Optimize image assets

## Maintainability
- Follow DRY principle
- Single responsibility per function
- Add meaningful comments
- Keep functions under 50 lines
- Avoid global state

## Testing
- Cover edge cases
- Include error scenarios
- Maintain 80%+ coverage
- Test negative cases