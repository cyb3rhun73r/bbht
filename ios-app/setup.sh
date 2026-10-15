#!/usr/bin/env bash
# Creates a fresh Expo project (latest SDK, matches the Expo Go app) and drops in our App.js
set -e
cd "$(dirname "$0")"
npx create-expo-app@latest KrishnaApp --template blank --no-install
cp App.js KrishnaApp/App.js
cd KrishnaApp && npm install
echo "Done. Ab: edit KrishnaApp/App.js (API_URL) phir 'npx expo start' chalao."
