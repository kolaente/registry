#!/bin/bash

# Test timing attack mitigation

echo "Testing timing attack mitigation..."
echo "This test verifies that valid and invalid usernames have similar response times"
echo ""

BASE_URL="http://localhost:5000/v2/token"

# Function to measure response time
measure_time() {
    local user=$1
    local pass=$2
    local label=$3

    # Make 5 requests and average the time
    total=0
    for i in {1..5}; do
        start=$(date +%s%N)
        curl -s -o /dev/null -u "$user:$pass" "$BASE_URL" 2>/dev/null
        end=$(date +%s%N)
        duration=$((($end - $start) / 1000000))  # Convert to milliseconds
        total=$(($total + $duration))
    done

    avg=$(($total / 5))
    echo "$label: ${avg}ms (average of 5 requests)"
    echo $avg
}

# Test 1: Valid user with wrong password
echo "Test 1: Valid user with wrong password"
time1=$(measure_time "admin" "wrongpassword" "Valid user, wrong password")

echo ""

# Test 2: Non-existent user
echo "Test 2: Non-existent user with any password"
time2=$(measure_time "nonexistentuser" "anypassword" "Non-existent user")

echo ""

# Calculate difference
diff=$(($time1 - $time2))
if [ $diff -lt 0 ]; then
    diff=$((-$diff))
fi

echo "Time difference: ${diff}ms"
echo ""

# Evaluate results
if [ $diff -lt 50 ]; then
    echo "✓ PASS: Timing difference is acceptable (<50ms)"
    echo "  Username enumeration via timing attack is mitigated"
else
    echo "✗ FAIL: Timing difference is too large (>50ms)"
    echo "  Potential username enumeration vulnerability!"
    exit 1
fi

# Both should take at least 50ms (bcrypt should be slow)
if [ $time1 -lt 50 ] || [ $time2 -lt 50 ]; then
    echo ""
    echo "⚠ WARNING: Responses are too fast (<50ms)"
    echo "  Bcrypt may not be running for all cases"
    exit 1
fi

echo ""
echo "✓ All timing attack mitigation tests passed!"
