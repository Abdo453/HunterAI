"""Bridge adapters connecting HunterAI intermediate representations and adjudication engines."""

from core.bridges.sir_to_court import sir_entity_to_claim, submit_sir_to_court

__all__ = [
    "sir_entity_to_claim",
    "submit_sir_to_court",
]
