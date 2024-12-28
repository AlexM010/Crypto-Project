#!/bin/bash
# Clean compiled files and temporary outputs in the scripts directory

echo "Cleaning ..."
# Remove compiled C files
find ./scripts -type f -name "*.out" -exec rm -v {} +

# Remove compiled Java class files
find ./scripts -type f -name "*.class" -exec rm -v {} +

echo "Cleanup completed."
