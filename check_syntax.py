import ast, os, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

root = r'E:\Agant\PentestAI-Unified'
new_files = [
    'core/planning/task_graph.py',
    'core/memory/triple_memory.py',
    'hunter_ai/orchestration/multi_agent_orchestrator.py',
    'hunter_ai/waf/waf_bypass_coordinator.py',
    'hunter_ai/hypo_engine/rag_hypo.py',
    'hunter_ai/orchestration/triple_agents.py',
    'pentest.py',
]

for f in new_files:
    fp = os.path.join(root, f)
    try:
        with open(fp, 'r', encoding='utf-8') as fh:
            content = fh.read()
        ast.parse(content)
        print('[OK] ' + f)
    except SyntaxError as e:
        print('[FAIL] ' + f + ':' + str(e.lineno) + ': ' + e.msg)
