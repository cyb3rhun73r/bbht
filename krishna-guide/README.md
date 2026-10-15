# Krishna Vani — Gita-inspired AI guide

User apni situation batata hai, AI Krishna ke roop mein Bhagavad Gita ke shlok aur vyavaharik margdarshan deta hai.

## Run
```bash
cd krishna-guide
pip install -r requirements.txt
cp .env.example .env   # ANTHROPIC_API_KEY daalo
uvicorn app:app --reload
```
Open http://localhost:8000

## Customize
- Persona/rules: `prompt.py`
- Model: `MODEL` env var
