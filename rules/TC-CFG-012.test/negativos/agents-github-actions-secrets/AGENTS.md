# CI

GitHub Actions secrets are configured in the repository settings.
Workflows reference them as `${{ secrets.NAME }}`. Never echo those values.
