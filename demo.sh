#!/bin/bash

echo "DNS over HTTPS (DOH) Demo Script"
echo "================================="
echo ""

# Check if the DNS server is running
echo "1. Starting DNS server..."
./dns-server -udp-port=:5353 -https-port=:8443 &
SERVER_PID=$!

# Wait for server to start
sleep 3

echo "2. Testing DOH POST method..."
# Create a simple DNS query for example.com
echo -n -e '\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' > /tmp/dns_query.bin

# Test POST method
echo "   Making POST request..."
curl -X POST https://localhost:8443/dns-query \
  -H "Content-Type: application/dns-message" \
  -H "Accept: application/dns-message" \
  --data-binary @/tmp/dns_query.bin \
  -k -w "HTTP Status: %{http_code}\n" \
  -o /tmp/doh_response.bin

if [ $? -eq 0 ]; then
    echo "   ✓ POST request successful"
    echo "   Response size: $(wc -c < /tmp/doh_response.bin) bytes"
else
    echo "   ✗ POST request failed"
fi

echo ""
echo "3. Testing DOH GET method..."
# Base64url encode the query
ENCODED_QUERY=$(base64 -i /tmp/dns_query.bin | tr '+/' '-_' | tr -d '=')

# Test GET method
echo "   Making GET request..."
curl "https://localhost:8443/dns-query?dns=${ENCODED_QUERY}" \
  -H "Accept: application/dns-message" \
  -k -w "HTTP Status: %{http_code}\n" \
  -o /tmp/doh_response_get.bin

if [ $? -eq 0 ]; then
    echo "   ✓ GET request successful"
    echo "   Response size: $(wc -c < /tmp/doh_response_get.bin) bytes"
else
    echo "   ✗ GET request failed"
fi

echo ""
echo "4. Testing traditional UDP DNS..."
# Test traditional DNS (requires dig)
if command -v dig >/dev/null 2>&1; then
    dig @localhost -p 5353 example.com +short
    if [ $? -eq 0 ]; then
        echo "   ✓ UDP DNS request successful"
    else
        echo "   ✗ UDP DNS request failed"
    fi
else
    echo "   dig not available, skipping UDP test"
fi

echo ""
echo "5. Cleanup..."
kill $SERVER_PID 2>/dev/null
rm -f /tmp/dns_query.bin /tmp/doh_response.bin /tmp/doh_response_get.bin

echo "Demo complete!"