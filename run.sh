#!/bin/bash
# Script to run files (Python, C, Java) from a specific folder.

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <folder_name>"
  exit 1
fi

TARGET_FOLDER="./scripts/$1"

if [ ! -d "$TARGET_FOLDER" ]; then
  echo "Error: Folder '$TARGET_FOLDER' does not exist."
  exit 1
fi

echo "Running scripts from: $TARGET_FOLDER"

# Run Python files
for py_file in "$TARGET_FOLDER"/*.py; do
  if [ -f "$py_file" ]; then
    echo "Running Python script: $py_file"
    python3 "$py_file"
    echo "-------------------------------------"
  fi
done

# Run compiled C programs
for c_out in "$TARGET_FOLDER"/*.out; do
  if [ -f "$c_out" ]; then
    echo "Running compiled C program: $c_out"
    "$c_out"
    echo "-------------------------------------"
  fi
done

# Run Java class files
for class_file in "$TARGET_FOLDER"/*.class; do
  if [ -f "$class_file" ]; then
    class_name=$(basename "$class_file" .class)
    echo "Running Java class: $class_name"
    java -cp "$TARGET_FOLDER" "$class_name"
    echo "-------------------------------------"
  fi
done

echo "Execution completed for folder: $TARGET_FOLDER"
