import json
import os
from pathlib import Path

from anthropic import AsyncAnthropic
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from prompt import SYSTEM_PROMPT

load_dotenv()
MODEL = os.getenv("MODEL", "claude-sonnet-5-5")
MAX_TURNS = 20  # keep only the recent conversation to bound cost

client = AsyncAnthropic()
app = FastAPI()
STATIC = Path(__file__).parent / "static"


class Message(BaseModel):
    role: str  # "user" | "assistant"
    content: str


class ChatRequest(BaseModel):
    messages: list[Message]


@app.post("/api/chat")
async def chat(req: ChatRequest):
    messages = [
        {"role": m.role, "content": m.content[:4000]}
        for m in req.messages[-MAX_TURNS:]
        if m.role in ("user", "assistant") and m.content.strip()
    ]

    async def stream():
        try:
            async with client.messages.stream(
                model=MODEL,
                max_tokens=700,
                system=SYSTEM_PROMPT,
                messages=messages,
            ) as s:
                async for text in s.text_stream:
                    yield f"data: {json.dumps({'t': text})}\n\n"
            yield "data: [DONE]\n\n"
        except Exception:
            err = "Kshama karo vatsa, abhi sampark nahi ho pa raha. Thodi der baad phir koshish karo."
            yield f"data: {json.dumps({'t': err})}\n\n"
            yield "data: [DONE]\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream")


@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
