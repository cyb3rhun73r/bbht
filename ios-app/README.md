# Krishna Vani — iPhone app (Expo / React Native)

Mac ya Xcode ki zarurat nahi. iPhone par **Expo Go** (App Store, free) se test hota hai.

## Steps (computer par, jo backend bhi chalayega)
1. Backend chalao (`../krishna-guide`):
   `uvicorn app:app --host 0.0.0.0 --port 8000`
2. Computer ka local IP nikalo (Mac: `ipconfig getifaddr en0`, Windows: `ipconfig`).
3. `./setup.sh` chalao, phir `KrishnaApp/App.js` mein `API_URL` ko `http://<IP>:8000` karo.
4. `cd KrishnaApp && npx expo start`
5. iPhone camera se QR scan karo → Expo Go mein khulega. Phone aur computer **same Wi-Fi** par hone chahiye.

Computer ke bina chalana ho to backend ko Render/Railway/Fly par deploy karke `https://...` URL `API_URL` mein daalo.
