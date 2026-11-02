import sys, os, json, time
sys.path.insert(0, '.')
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

print("=" * 70)
print("الاختبار الوظيفي الشامل النهائي — جميع الميزات المحسنة")
print("=" * 70)

# [1] TDG
print("\n[1] TDG مع دعم async...")
from core.planning.task_graph import TaskDependencyGraph

graph = TaskDependencyGraph(graph_id="test_tdg")
t1 = graph.add_task("recon", "recon", "example.com")
t2 = graph.add_task("scan", "scan", "example.com", dependencies=[t1])
t3 = graph.add_task("exploit", "exploit", "example.com", dependencies=[t2])
graph.mark_completed(t1, {"subdomains": 3})
graph.mark_completed(t2, {"ports": [80, 443]})
graph.mark_completed(t3, {"findings": ["xss"]})
print(f"  المهام: 3 (كلها مكتملة)")
print(f"  الحالة: {graph.get_status_summary()}")
graph.save()
print("  OK تم الحفظ")

# [2] Triple Memory
print("\n[2] الذاكرة الثلاثية...")
from core.memory.triple_memory import TripleMemory, MemoryType
mem = TripleMemory()
mem.write_working("example.com", "token", "abc123")
mem.write_semantic("example.com", "server", "nginx")
mem.record_failure("example.com", "sqli", "WAF blocked")
r1 = mem.read(MemoryType.WORKING, "example.com", "token")
r2 = mem.read(MemoryType.SEMANTIC, "example.com", "server")
print(f"  القراءة العاملة: {r1.value if r1 else 'None'}")
print(f"  القراءة الدلالية: {r2.value if r2 else 'None'}")
print(f"  الإحصائيات: {mem.stats()}")

# [3] Triple Agents
print("\n[3] ثلاثي الوكلاء...")
from hunter_ai.orchestration.triple_agents import TripleAgentSystem, Verdict
system = TripleAgentSystem(graph_id="test_triple")
plan = system.plan_and_execute("example.com", "xss", "XSS test")
exec_res = system.execute_task(plan["executor_task"], {"vuln": True})
review_res = system.review_task(plan["reviewer_task"], court_verdict="allowed")
print(f"  الخطة: {plan['status']}")
print(f"  التنفيذ: {exec_res.status}")
print(f"  المراجعة: {review_res.verdict.value}")
print(f"  الإحصائيات: {json.dumps(system.stats(), ensure_ascii=False)}")

# [4] WAF Bypass + Evidence Court
print("\n[4] WAF Bypass + Evidence Court...")
from hunter_ai.waf.waf_bypass_coordinator import WAFBypassCoordinator
from hunter_ai.evidence.evidence_court import BypassContext, evidence_court
context = BypassContext(
    target="example.com", endpoint="/search",
    original_payload="' OR 1=1 --", bypass_payload="%27%20OR%201%3D1%20--",
    waf_type="cloudflare", waf_detected=True, status_code=200,
    response_body="<html>Welcome</html>", response_headers={"server": "cloudflare"},
    request_headers={"user-agent": "HunterAI"}, response_time_ms=150.0,
    technique_level="url_encoding",
)
court_result = evidence_court.verify_bypass(context, case_id="final_test_001")
print(f"  حكم المحكمة: {court_result.verdict.value}")
print(f"  الثقة: {court_result.confidence:.2f}")
print(f"  التجاوز مؤكد: {court_result.bypass_confirmed}")
print(f"  إحصائيات المحكمة: {json.dumps(evidence_court.stats(), ensure_ascii=False)}")

# [5] RAG Hypothesis
print("\n[5] RAG Hypothesis Engine...")
from hunter_ai.hypo_engine.rag_hypo import RAGHypothesisEngine
engine = RAGHypothesisEngine()
hyps = engine.generate_hypothesis("example.com", "/search", "input reflected", top_k=3, min_score=0.1)
print(f"  عدد الفرضيات: {len(hyps)}")
for h in hyps:
    print(f"    • {h['technique']} (الثقة: {h['confidence']:.2f})")

# [6] Config
print("\n[6] الإعدادات المركزية...")
from core.config.settings import config
print(f"  Ollama Host: {config.ollama.host}")
print(f"  WAF Timeout: {config.waf.timeout_seconds}s")
print(f"  Debug: {config.debug}")

# [7] Logging
print("\n[7] نظام السجلات...")
from core.logging.logger import logger
logger.info("[Test] اختبار السجلات المحسن")
print("  OK السجلات تعمل")

print("\n" + "=" * 70)
print("الاختبار الوظيفي الشامل انتهى بنجاح!")
print("=" * 70)
