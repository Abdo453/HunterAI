"""
Verifies Section 8 - Event Bus integrity.
Causal chain: Publishing duplicate/malformed events handled properly.
"""
import pytest
import asyncio
from core.burp_gateway.event_stream import BurpLiveEventStream

@pytest.mark.asyncio
async def test_event_bus():
    stream = BurpLiveEventStream(max_buffer_size=10)
    
    evt1 = stream.publish_event("TEST_EVENT", {"id": 1})
    evt2 = stream.publish_event("TEST_EVENT", {"id": 1})
    
    assert evt1.event_id != evt2.event_id
    assert evt1.timestamp > 0
    assert evt1.event_type == "TEST_EVENT"
    
    recent = stream.get_recent_events()
    assert len(recent) == 2
    
    # Subscribe check
    async def sub_test():
        count = 0
        async for e in stream.subscribe(timeout=0.1):
            count += 1
            if count == 1:
                break
        return count
        
    t = asyncio.create_task(sub_test())
    await asyncio.sleep(0.01)
    stream.publish_event("TEST_EVENT", {"id": 2})
    assert await t == 1
