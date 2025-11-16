#!/bin/bash

# Test rate limiting functionality

echo "Testing rate limiting..."

# Start registry (assumes it's running on localhost:5000)
BASE_URL="http://localhost:5000"

# Test 1: Multiple requests to token endpoint
echo "Test 1: Sending 25 rapid requests to /v2/token..."
success=0
rate_limited=0

for i in {1..25}; do
    response=$(curl -s -o /dev/null -w "%{http_code}" -u admin:wrongpass "$BASE_URL/v2/token?scope=repository:test:pull" 2>/dev/null)

    if [ "$response" = "401" ] || [ "$response" = "200" ]; then
        ((success++))
    elif [ "$response" = "429" ]; then
        ((rate_limited++))
    fi
done

echo "Results: $success allowed, $rate_limited rate-limited"

if [ $rate_limited -gt 0 ]; then
    echo "✓ Rate limiting is working!"
else
    echo "✗ Rate limiting may not be working properly"
    exit 1
fi

# Test 2: Wait and retry (should work after rate limit window)
echo ""
echo "Test 2: Waiting 2 seconds and retrying..."
sleep 2

response=$(curl -s -o /dev/null -w "%{http_code}" -u admin:wrongpass "$BASE_URL/v2/token" 2>/dev/null)

if [ "$response" = "401" ]; then
    echo "✓ Rate limit reset successfully"
else
    echo "✗ Unexpected response: $response"
fi

echo ""
echo "Rate limiting tests complete!"
