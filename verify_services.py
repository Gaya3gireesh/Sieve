import asyncio
import logging
import sys
# Make sure we can import from app
sys.path.append('.')

from app.config import get_settings
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
from groq import Groq
import redis.asyncio as redis
import httpx
from github import Auth, Github

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Add immediate flush for debugging
def debug_print(msg):
    print(msg, flush=True)

debug_print("Imports complete. Starting verification...")

async def verify_grok():
    settings = get_settings()
    logger.info(f"Verifying Grok API (Model: {settings.groq_model})...")
    try:
        client = Groq(api_key=settings.groq_api_key)
        response = client.chat.completions.create(
            model=settings.groq_model,
            messages=[{"role": "user", "content": "Hello"}],
            max_tokens=5
        )
        content = response.choices[0].message.content
        logger.info(f"✅ Grok API is working. Response: {content!r}")
        return True
    except Exception as e:
        logger.error(f"❌ Grok API failed: {e}")
        return False

async def verify_redis():
    settings = get_settings()
    logger.info("Verifying Redis...")
    try:
        r = redis.from_url(settings.redis_url)
        await r.ping()
        logger.info("✅ Redis is reachable.")
        await r.aclose()
        return True
    except Exception as e:
        logger.error(f"❌ Redis failed: {e}")
        return False

async def verify_github():
    settings = get_settings()
    logger.info("Verifying GitHub API token...")
    try:
        gh = Github(auth=Auth.Token(settings.github_token))
        login = gh.get_user().login
        logger.info(f"✅ GitHub token is valid. Authenticated as: {login}")
        return True
    except Exception as e:
        if settings.github_token_is_placeholder:
            logger.error(
                f"❌ GitHub failed: {e} | hint: GITHUB_TOKEN appears to be placeholder."
            )
        else:
            logger.error(f"❌ GitHub failed: {e}")
        return False

async def verify_supabase():
    settings = get_settings()
    logger.info("Verifying Supabase...")
    try:
        if settings.supabase_uses_postgres:
            engine = create_async_engine(settings.supabase_url)
            async with engine.connect() as conn:
                result = await conn.execute(text("SELECT 1"))
                logger.info(
                    f"✅ Supabase (PostgreSQL) is reachable. Result: {result.scalar()}"
                )
            await engine.dispose()
        else:
            auth_health_endpoint = f"{settings.supabase_rest_base_url}/auth/v1/health"
            auth_headers = {
                "apikey": settings.supabase_key,
                "Authorization": f"Bearer {settings.supabase_key}",
            }
            async with httpx.AsyncClient(timeout=settings.supabase_http_timeout_sec) as client:
                auth_resp = await client.get(auth_health_endpoint, headers=auth_headers)
                if auth_resp.status_code >= 400:
                    raise RuntimeError(
                        f"Supabase auth health failed ({auth_resp.status_code}) at "
                        f"{auth_health_endpoint}: {auth_resp.text[:180]}"
                    )
            logger.info(
                "✅ Supabase auth endpoint is reachable (status: %s).",
                auth_resp.status_code,
            )

            if settings.supabase_probe_rest_table:
                endpoint = (
                    f"{settings.supabase_rest_base_url}/rest/v1/pr_scans?select=id&limit=1"
                )
                headers = {
                    "apikey": settings.supabase_key,
                    "Authorization": f"Bearer {settings.supabase_key}",
                }
                async with httpx.AsyncClient(
                    timeout=settings.supabase_http_timeout_sec
                ) as client:
                    resp = await client.get(endpoint, headers=headers)
                if resp.status_code >= 400:
                    raise RuntimeError(
                        f"Supabase REST check failed ({resp.status_code}): {resp.text[:180]}"
                    )
                logger.info("✅ Supabase REST table probe is reachable.")
        return True
    except Exception as e:
        detail = str(e)
        if "Name or service not known" in detail or "Could not resolve host" in detail:
            detail = (
                f"{detail} | hint: verify SUPABASE_URL project ref in Supabase Settings > API."
            )
        logger.error(f"❌ Supabase failed: {detail}")
        return False

async def main():
    logger.info("Starting verification of external services...")
    
    # Run tests
    # Note: We run sequentially to clearly see output
    grok_ok = await verify_grok()
    redis_ok = await verify_redis()
    github_ok = await verify_github()
    supabase_ok = await verify_supabase()

    if grok_ok and redis_ok and github_ok and supabase_ok:
        logger.info("\n🎉 All services are verified and working!")
        sys.exit(0)
    else:
        logger.error("\n⚠️ Some services failed verification.")
        sys.exit(1)

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
