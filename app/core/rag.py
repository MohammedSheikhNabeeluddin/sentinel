"""
RAG for Sentinel - Retrieval Augmented Generation over compliance / risk docs
- Chunking, embedding via NVIDIA (nvidia/nv-embedqa-mistral-7b-v2) with local fallback (sentence-transformers)
- FAISS vector store at data/vector.index
- Query: retrieve top-k chunks + call Nemotron 3 Ultra
"""
import os
import json
import pickle
from pathlib import Path
from typing import List, Dict, Any, Optional

# Try imports
try:
    import faiss
    import numpy as np
    FAISS_AVAILABLE = True
except:
    FAISS_AVAILABLE = False
    faiss = None
    np = None

try:
    from sentence_transformers import SentenceTransformer
    ST_AVAILABLE = True
except:
    ST_AVAILABLE = False
    SentenceTransformer = None

from openai import OpenAI

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)
INDEX_PATH = DATA_DIR / "vector.index"
META_PATH = DATA_DIR / "vector_meta.pkl"
DOCS_PATH = DATA_DIR / "docs.json"

# Default compliance docs to seed RAG if none uploaded
DEFAULT_DOCS = [
    {"id":"iso27001-a8.26","text":"ISO 27001 A.8.26 Application security: Applications must be securely developed. SQL injection must be prevented via parameterized queries, input validation, and WAF. Critical vulns must be patched within 7 days.","source":"ISO27001"},
    {"id":"nist-prds7","text":"NIST PR.DS-7: Development lifecycle is protected. Secure code review, SAST/DAST, and RCE patching required. MFA for privileged access reduces lateral movement.","source":"NIST"},
    {"id":"cis-3.3","text":"CIS 3.3 Configure Data Access Controls: IDOR must be mitigated via authorization checks on every object access. Enforce least privilege and audit access logs.","source":"CIS"},
    {"id":"rbi-annex","text":"RBI Cyber Framework Annex 1-8: Banks must perform quarterly pentests, fix critical vulns in 14 days, maintain EDR and SIEM monitoring for RCE and SSRF.","source":"RBI"},
    {"id":"sebi-15","text":"SEBI CSCRF 15.1: Vulnerability assessment for all internet-facing apps monthly. XSS and exposure of secrets must be vaulted via HSM. Risk quantification in INR Cr required for board.","source":"SEBI"},
    {"id":"eal-def","text":"Expected Annual Loss (EAL) = Single Loss Expectancy (SLE) × Annualized Rate of Occurrence (ARO). Value at Risk 95 (VaR95) is the 95th percentile of Monte Carlo simulated annual loss distribution.","source":"RiskEngine"},
]

def _get_embed_client():
    key = os.getenv("NVIDIA_API_KEY") or os.getenv("LLM_API_KEY","")
    endpoint = os.getenv("NVIDIA_ENDPOINT","https://integrate.api.nvidia.com/v1")
    # NVIDIA embedding model
    embed_model = os.getenv("NVIDIA_EMBED_MODEL","nvidia/nv-embedqa-mistral-7b-v2")
    if key:
        client = OpenAI(base_url=endpoint, api_key=key, timeout=60.0)
        return client, embed_model
    return None, embed_model

# Local fallback model singleton
_st_model = None
def _get_st_model():
    global _st_model
    if not ST_AVAILABLE:
        return None
    if _st_model is None:
        _st_model = SentenceTransformer("all-MiniLM-L6-v2")
    return _st_model

def chunk_text(text: str, size=500, overlap=80):
    chunks = []
    for i in range(0, len(text), size-overlap):
        c = text[i:i+size]
        if c.strip():
            chunks.append(c)
        if i+size >= len(text):
            break
    return chunks

def embed_texts(texts: List[str]) -> List[List[float]]:
    # Try NVIDIA first
    client, model = _get_embed_client()
    if client:
        try:
            # NVIDIA embeddings: use embeddings.create
            resp = client.embeddings.create(input=texts, model=model)
            # openai returns data sorted
            embs = [d.embedding for d in sorted(resp.data, key=lambda x: x.index)]
            return embs
        except Exception as e:
            # fallback to local
            pass
    # Local fallback
    st = _get_st_model()
    if st:
        embs = st.encode(texts, convert_to_numpy=True)
        return embs.tolist()
    # Last fallback: random
    import random, hashlib
    # deterministic pseudo-embedding
    out=[]
    for t in texts:
        h=int(hashlib.md5(t.encode()).hexdigest()[:8],16)
        random.seed(h)
        out.append([random.random() for _ in range(384)])
    return out

class RAGStore:
    def __init__(self):
        self.index = None
        self.metas: List[Dict] = []
        self.dim = 384
        self._load()

    def _load(self):
        if not FAISS_AVAILABLE:
            return
        if INDEX_PATH.exists() and META_PATH.exists():
            try:
                self.index = faiss.read_index(str(INDEX_PATH))
                with open(META_PATH,"rb") as f:
                    self.metas = pickle.load(f)
                self.dim = self.index.d
            except:
                self.index = None
                self.metas = []
        # Ensure docs exist
        if not self.metas and DEFAULT_DOCS:
            self.ingest_docs(DEFAULT_DOCS)

    def _save(self):
        if not FAISS_AVAILABLE or self.index is None:
            return
        faiss.write_index(self.index, str(INDEX_PATH))
        with open(META_PATH,"wb") as f:
            pickle.dump(self.metas, f)
        # also save docs.json
        with open(DOCS_PATH,"w") as f:
            json.dump(self.metas, f, indent=2)

    def ingest_docs(self, docs: List[Dict]):
        """docs: [{id, text, source}] -> chunk and embed"""
        if not FAISS_AVAILABLE:
            # fallback without faiss: just store
            self.metas.extend(docs)
            return
        texts=[]
        metas=[]
        for d in docs:
            chunks = chunk_text(d["text"])
            for i,ch in enumerate(chunks):
                texts.append(ch)
                metas.append({"id": f"{d['id']}#c{i}", "text": ch, "source": d.get("source","doc")})
        if not texts:
            return
        embs = embed_texts(texts)
        import numpy as np
        arr = np.array(embs).astype("float32")
        # normalize for cosine via inner product
        faiss.normalize_L2(arr)
        if self.index is None:
            self.dim = arr.shape[1]
            self.index = faiss.IndexFlatIP(self.dim)
        self.index.add(arr)
        self.metas.extend(metas)
        self._save()

    def retrieve(self, query: str, k=3) -> List[Dict]:
        if not FAISS_AVAILABLE or self.index is None or not self.metas:
            # fallback keyword search
            ql=query.lower()
            scored=[]
            for m in self.metas:
                score = sum(ql.count(w) for w in m["text"].lower().split()[:20])
                scored.append((score,m))
            scored.sort(key=lambda x: x[0], reverse=True)
            return [m for _,m in scored[:k]]
        q_emb = embed_texts([query])[0]
        import numpy as np
        q_arr = np.array([q_emb]).astype("float32")
        faiss.normalize_L2(q_arr)
        D, I = self.index.search(q_arr, min(k, len(self.metas)))
        res=[]
        for idx in I[0]:
            if 0 <= idx < len(self.metas):
                res.append(self.metas[idx])
        return res

    def clear(self):
        self.index = None
        self.metas = []
        if INDEX_PATH.exists():
            INDEX_PATH.unlink()
        if META_PATH.exists():
            META_PATH.unlink()
        if DOCS_PATH.exists():
            DOCS_PATH.unlink()

rag_store = RAGStore()

def rag_query(question: str, risk_context: Dict = None) -> Dict[str, Any]:
    """Retrieve + call Nemotron 3 Ultra"""
    chunks = rag_store.retrieve(question, k=3)
    context = "\n".join([f"[{c['source']}] {c['text']}" for c in chunks])
    # Build prompt with risk context if provided
    risk_str = ""
    if risk_context:
        risk_str = f"Live risk: EAL ₹{risk_context.get('org',{}).get('total_eal_cr',0):.2f}Cr, vulns {risk_context.get('org',{}).get('vuln_count',0)}"
    # Call Nemotron via ai_decision client
    from app.core.ai_decision import get_nvidia_client
    client, model, key, endpoint = get_nvidia_client()
    if not client or not key:
        # fallback answer using retrieved chunks
        ans = f"Based on retrieved docs: {chunks[0]['text'][:300]} ... Risk: {risk_str}"
        return {"answer": ans, "sources": chunks, "model": "fallback-rag", "retrieved": chunks}
    try:
        messages=[
            {"role":"system","content":"You are a CISO RAG assistant. Answer using ONLY the retrieved context below. Cite sources. If context insufficient, say so. Context:\n"+context},
            {"role":"user","content": f"{risk_str}\nQuestion: {question}"}
        ]
        extra={"chat_template_kwargs":{"enable_thinking":True}} if "nemotron" in model.lower() else {}
        resp=client.chat.completions.create(model=model, messages=messages, temperature=0.2, max_tokens=800, extra_body=extra if extra else None)
        content=resp.choices[0].message.content
        reasoning=getattr(resp.choices[0].message, "reasoning_content", None)
        return {"answer": content, "sources": chunks, "model": model, "reasoning": reasoning, "retrieved": chunks}
    except Exception as e:
        return {"answer": f"RAG retrieval: {chunks[0]['text'][:300]} [LLM error: {str(e)[:200]}]", "sources": chunks, "model": model, "error": str(e)[:300], "retrieved": chunks}
