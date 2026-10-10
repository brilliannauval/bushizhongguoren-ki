from fastapi import APIRouter

from . import auth, items, jobs, profiles, system

router = APIRouter()
for feature_router in (system.router, auth.router, items.router, profiles.router, jobs.router):
    router.include_router(feature_router)
