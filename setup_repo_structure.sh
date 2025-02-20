#!/bin/bash

# Define the base structure
DIRECTORIES=(
  "analyst-notebook"
  "backend/app"
  "backend/config"
  "backend/static"
  "backend/templates"
  "email-analyzer"
  "email-client-addin"
  "tests"
  "docs"
  "scripts"
)

# Create directories if they don't exist
echo "Creating project directories..."
for dir in "${DIRECTORIES[@]}"; do
  mkdir -p "$dir"
done

# Move existing files if they exist
echo "Organizing files..."

# Move backend-related files
mv reporter-tool/* backend/ 2>/dev/null

# Move specific components if they exist
mv backend/reporter-tool analyst-notebook/ 2>/dev/null
mv backend/email_analyzer email-analyzer/ 2>/dev/null
mv backend/email_client_addin email-client-addin/ 2>/dev/null

# Move existing test files
if [ -d "backend/tests" ]; then
  mv backend/tests/* tests/ 2>/dev/null
fi

# Move documentation files
mv backend/docs/* docs/ 2>/dev/null

# Move scripts
mv backend/scripts/* scripts/ 2>/dev/null

# Move general files to root if they exist
mv backend/README.md README.md 2>/dev/null
mv backend/LICENSE LICENSE 2>/dev/null
mv backend/requirements.txt requirements.txt 2>/dev/null

# Stage and commit the changes
echo "Updating Git repository..."
git add .
git commit -m "Reorganized project structure"

echo "Repository has been restructured successfully!"