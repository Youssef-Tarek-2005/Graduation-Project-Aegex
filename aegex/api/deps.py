"""Shared objects for the API: settings and database clients (created once, reused by every route)."""
from ..config import get_settings
from ..intel.retriever import KnowledgeRetriever
from ..storage.es_store import ElasticStore
from ..storage.postgres_store import PostgresStore

settings = get_settings()
pg = PostgresStore(settings.postgres_url)
es = ElasticStore(settings)
retriever = KnowledgeRetriever()
