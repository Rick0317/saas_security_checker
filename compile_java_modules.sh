#!/bin/bash

# ZAP Java Security Modules Compilation Script
# This script compiles the Java security modules for integration with the SaaS Security Checker

echo "🚀 Starting ZAP Java Security Modules compilation..."

# Set directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAVA_MODULES_DIR="$SCRIPT_DIR/java_security_modules"
ZAPROXY_DIR="$SCRIPT_DIR/zaproxy-main"
CLASSES_DIR="$JAVA_MODULES_DIR/classes"

# Check if Java is available
if ! command -v javac &> /dev/null; then
    echo "❌ Error: Java compiler (javac) not found. Please install Java JDK."
    exit 1
fi

if ! command -v java &> /dev/null; then
    echo "❌ Error: Java runtime not found. Please install Java JDK."
    exit 1
fi

echo "✅ Java compiler found: $(javac -version)"

# Create classes directory
mkdir -p "$CLASSES_DIR"
echo "📁 Created classes directory: $CLASSES_DIR"

# Build classpath
CLASSPATH_PARTS=(
    "$JAVA_MODULES_DIR"
    "$ZAPROXY_DIR/zap/src/main/java"
)

# Find JAR files in zaproxy directory
echo "🔍 Scanning for JAR files..."
JAR_COUNT=0
for jar_file in $(find "$ZAPROXY_DIR" -name "*.jar" 2>/dev/null); do
    CLASSPATH_PARTS+=("$jar_file")
    JAR_COUNT=$((JAR_COUNT + 1))
done

echo "📦 Found $JAR_COUNT JAR files"

# Add system Java classes (macOS/Linux)
if [[ -f "/System/Library/Frameworks/JavaVM.framework/Classes/classes.jar" ]]; then
    CLASSPATH_PARTS+=("/System/Library/Frameworks/JavaVM.framework/Classes/classes.jar")
    echo "🍎 Using macOS system Java classes"
fi

# Build classpath string
CLASSPATH=$(IFS=':'; echo "${CLASSPATH_PARTS[*]}")
echo "🔗 Built classpath with ${#CLASSPATH_PARTS[@]} components"

# Check if Java source files exist
JAVA_FILES=$(find "$JAVA_MODULES_DIR" -name "*.java" 2>/dev/null | wc -l)
if [ "$JAVA_FILES" -eq 0 ]; then
    echo "❌ Error: No Java source files found in $JAVA_MODULES_DIR"
    exit 1
fi

echo "📄 Found $JAVA_FILES Java source files"

# Compile Java files one by one
echo "🔨 Compiling Java modules..."
COMPILE_SUCCESS=0
COMPILE_ERRORS=0

for java_file in "$JAVA_MODULES_DIR"/*.java; do
    if [[ -f "$java_file" ]]; then
        filename=$(basename "$java_file")
        echo "   📝 Compiling $filename..."
        
        if javac -cp "$CLASSPATH" -d "$CLASSES_DIR" "$java_file"; then
            echo "   ✅ $filename compiled successfully"
            COMPILE_SUCCESS=$((COMPILE_SUCCESS + 1))
        else
            echo "   ❌ Failed to compile $filename"
            COMPILE_ERRORS=$((COMPILE_ERRORS + 1))
        fi
    fi
done

echo ""
echo "📊 Compilation Summary:"
echo "   ✅ Successful: $COMPILE_SUCCESS"
echo "   ❌ Failed: $COMPILE_ERRORS"

if [ $COMPILE_ERRORS -eq 0 ]; then
    echo ""
    echo "🎉 All Java security modules compiled successfully!"
    echo "📁 Compiled classes are available in: $CLASSES_DIR"
    
    # List compiled classes
    echo ""
    echo "📋 Compiled classes:"
    find "$CLASSES_DIR" -name "*.class" | while read -r class_file; do
        echo "   $(basename "$class_file")"
    done
    
    echo ""
    echo "🚀 Java security modules are ready for integration!"
    echo "   Run 'python main.py' to execute security tests including Java modules"
    
else
    echo ""
    echo "⚠️  Some modules failed to compile. Check error messages above."
    echo "   Fix compilation errors and run this script again."
    exit 1
fi
