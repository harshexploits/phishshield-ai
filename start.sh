#!/bin/bash
mkdir -p /app/public
echo "google.com, pub-3382996367685285, DIRECT, f08c47fec0942fa0" > /app/public/ads.txt
streamlit run app.py --server.port=$PORT --server.headless=true --server.address=0.0.0.0 --browser.serverAddress=0.0.0.0
