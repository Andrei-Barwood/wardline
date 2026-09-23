with open("src/wardline/runtime.py") as f:
    text = f.read()

append = """    state.circuit_breakers = CircuitBreakerRegistry(
        threshold=state.settings.circuit_breaker_threshold,
        window_seconds=state.settings.circuit_breaker_window_seconds,
        open_seconds=state.settings.circuit_breaker_open_seconds,
        audit_callback=_audit,
        clock=active_clock,
    )
"""
text = text.replace("    return state", append + "    return state")

with open("src/wardline/runtime.py", "w") as f:
    f.write(text)
