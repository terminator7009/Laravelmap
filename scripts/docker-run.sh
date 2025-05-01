#!/bin/bash
# LaravelMap Docker Helper Script
# This script simplifies running LaravelMap in Docker

# Default values
TARGET_URL=""
OUTPUT_FORMAT="text"
OUTPUT_FILE=""
THREADS=5
RISK_LEVEL="medium"
SCAN_CATEGORIES="all"

# Display help message
show_help() {
    echo "LaravelMap Docker Helper Script"
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -u, --url URL          Target URL to scan (required)"
    echo "  -o, --output FILE      Output file path"
    echo "  -f, --format FORMAT    Output format (text, json, html) [default: text]"
    echo "  -t, --threads NUM      Number of threads [default: 5]"
    echo "  -r, --risk-level LVL   Risk level (low, medium, high) [default: medium]"
    echo "  -c, --categories CATS  Scan categories (comma-separated) [default: all]"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Example:"
    echo "  $0 --url https://example.com --output report.json --format json"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -u|--url)
            TARGET_URL="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -f|--format)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        -t|--threads)
            THREADS="$2"
            shift 2
            ;;
        -r|--risk-level)
            RISK_LEVEL="$2"
            shift 2
            ;;
        -c|--categories)
            SCAN_CATEGORIES="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Check if target URL is provided
if [ -z "$TARGET_URL" ]; then
    echo "Error: Target URL is required"
    show_help
    exit 1
fi

# Create reports directory if it doesn't exist
mkdir -p reports

# Build command arguments
CMD_ARGS="-url $TARGET_URL -threads $THREADS -risk-level $RISK_LEVEL -categories $SCAN_CATEGORIES"

# Add output file if specified
if [ ! -z "$OUTPUT_FILE" ]; then
    # If output file doesn't have a path, put it in reports directory
    if [[ "$OUTPUT_FILE" != */* ]]; then
        OUTPUT_FILE="reports/$OUTPUT_FILE"
    fi
    
    # Map to container path
    CONTAINER_OUTPUT="/app/$(basename $OUTPUT_FILE)"
    CMD_ARGS="$CMD_ARGS -output $CONTAINER_OUTPUT -format $OUTPUT_FORMAT"
    
    echo "Output will be saved to: $OUTPUT_FILE"
fi

# Run LaravelMap in Docker
echo "Starting LaravelMap scan against $TARGET_URL..."
docker run --rm -v "$(pwd)/reports:/app/reports" laravelmap $CMD_ARGS

# Check if Docker command was successful
if [ $? -eq 0 ]; then
    echo "Scan completed successfully!"
    if [ ! -z "$OUTPUT_FILE" ]; then
        echo "Results saved to: $OUTPUT_FILE"
    fi
else
    echo "Scan failed. Please check the error messages above."
fi
