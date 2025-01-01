#!/bin/bash
# Compile all C and Java files in the scripts directory

echo "Compiling all C and Java files..."

# Compile all C files
for dir in ./scripts/*/; do
  for c_file in "$dir"*.c; do
    if [ -f "$c_file" ]; then
      output="${c_file%.c}.out"
      echo "Compiling $c_file..."
      gcc -o "$output" "$c_file" -lcrypto
      if [ $? -eq 0 ]; then
        echo "Compiled: $output"
      else
        echo "Compilation failed for $c_file"
      fi
    fi
  done
done

# Compile all Java files
for dir in ./scripts/*/; do
  for java_file in "$dir"*.java; do
    if [ -f "$java_file" ]; then
      echo "Compiling $java_file..."
      javac "$java_file"
      if [ $? -eq 0 ]; then
        echo "Compiled: ${java_file%.java}.class"
      else
        echo "Compilation failed for $java_file"
      fi
    fi
  done
done

echo "Compilation process completed."
