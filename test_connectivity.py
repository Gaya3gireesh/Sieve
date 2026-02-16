"""
Quick connectivity test for Groq API, Redis, and Supabase.
Each test has its own timeout so a single failing service doesn't block the rest.
"""
import asyncio
import os
import sys
import signal

# Load .env manually
from pathlib import Path
env_path = Path(__file__).parent / ".env"
if env_path.exists():
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

TIMEOUT = 15  # seconds per test


# ── 1. Groq API ──────────────────────────────────────────────────────────────
def test_groq():
    print("\n🔍 Testing Groq API...", flush=True)
    try:
        from groq import Groq
        api_key = os.environ.get("GROQ_API_KEY", "")
        if not api_key:
            print("   ❌ GROQ_API_KEY not set in .env", flush=True)
            return False
        client = Groq(api_key=api_key)
        resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": "Say hello in one word."}],
            max_tokens=5,
        )
        content = resp.choices[0].message.content
        print(f"   ✅ Groq API is working.  Response: {content!r}", flush=True)
        return True
    except Exception as e:
        print(f"   ❌ Groq API failed: {e}", flush=True)
        return False


# ── 2. Redis (Upstash) ──────────────────────────────────────────────────────
async def test_redis():
    print("\n🔍 Testing Redis (Upstash)...", flush=True)
    try:
        import redis.asyncio as aioredis
        redis_url = os.environ.get("REDIS_URL", "")
        if not redis_url:
            print("   ❌ REDIS_URL not set in .env", flush=True)
            return False
        r = aioredis.from_url(redis_url)
        pong = await asyncio.wait_for(r.ping(), timeout=TIMEOUT)
        print(f"   ✅ Redis is reachable.  PING → {pong}", flush=True)
        await r.aclose()
        return True
    except asyncio.TimeoutError:
        print(f"   ❌ Redis timed out after {TIMEOUT}s", flush=True)
        return False
    except Exception as e:
        print(f"   ❌ Redis failed: {e}", flush=True)
        return False


# ── 3. Supabase (PostgreSQL) ────────────────────────────────────────────────
async def test_supabase():
    print("\n🔍 Testing Supabase (PostgreSQL)...", flush=True)
    try:
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy import text
        db_url = os.environ.get("SUPABASE_URL", "")
        if not db_url:
            print("   ❌ SUPABASE_URL not set in .env", flush=True)
            return False
        if not db_url.startswith("postgresql"):
            print(f"   ⚠️  SUPABASE_URL is not a PostgreSQL DSN ({db_url[:30]}...)", flush=True)
            return False
        engine = create_async_engine(db_url, connect_args={"timeout": TIMEOUT})
        async with engine.connect() as conn:
            result = await asyncio.wait_for(
                conn.execute(text("SELECT 1")), timeout=TIMEOUT
            )
            val = result.scalar()
        await engine.dispose()
        print(f"   ✅ Supabase PostgreSQL is reachable.  SELECT 1 → {val}", flush=True)
        return True
    except asyncio.TimeoutError:
        print(f"   ❌ Supabase timed out after {TIMEOUT}s", flush=True)
        return False
    except Exception as e:
        print(f"   ❌ Supabase failed: {e}", flush=True)
        return False


# ── Main ─────────────────────────────────────────────────────────────────────
async def main():
    print("=" * 60, flush=True)
    print("  Backend Connectivity Test", flush=True)
    print("=" * 60, flush=True)

    groq_ok = test_groq()                     # sync (HTTP, not async)
    redis_ok = await test_redis()             # async
    supabase_ok = await test_supabase()       # async

    print("\n" + "=" * 60, flush=True)
    print("  Summary", flush=True)
    print("=" * 60, flush=True)
    print(f"  Groq API  : {'✅ PASS' if groq_ok else '❌ FAIL'}", flush=True)
    print(f"  Redis     : {'✅ PASS' if redis_ok else '❌ FAIL'}", flush=True)
    print(f"  Supabase  : {'✅ PASS' if supabase_ok else '❌ FAIL'}", flush=True)
    print("=" * 60, flush=True)

    all_ok = groq_ok and redis_ok and supabase_ok
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    asyncio.run(main())
