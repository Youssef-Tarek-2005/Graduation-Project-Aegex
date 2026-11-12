from fastapi import APIRouter, Query

from ...intel.knowledge_base import CATEGORY_PROFILE, references_for
from ..deps import retriever

router = APIRouter(prefix="/api/v1/intel", tags=["Threat intelligence"])


@router.get("/layers", summary="Layers of the knowledge base",
            description="MITRE ATT&CK, OWASP IoT Top 10, CVE/NVD, CWE/CAPEC and threat-intelligence feeds, with entry counts.")
def layers() -> dict:
    return {"layers": retriever.layers()}


@router.get("/search", summary="Search the knowledge base",
            description="Keyword retriever over all layers. Try `mirai`, `camera`, `ddos`, `T1486` or `default credentials`.")
def search(q: str = Query(..., min_length=2, max_length=200), layer: str | None = Query(None, description="Limit to one layer, e.g. mitre_attack"),
           limit: int = Query(8, ge=1, le=30)) -> dict:
    return {"query": q, "results": retriever.search(q, layer, limit)}


@router.get("/categories", summary="Attack scenarios with their linked references and mitigations")
def categories() -> dict:
    return {"categories": [{"category": k, "title": v["title"], "base_severity": v["base_severity"], "mitigations": v["mitigations"],
                            "references": references_for(k)} for k, v in CATEGORY_PROFILE.items()]}
