from secagent.routing import route_agents


def test_full_plan_includes_sast_and_critic():
    plan = route_agents("full")
    assert "semgrep" in plan
    assert "builtin_sast" in plan
    assert plan[-1] == "critic"


def test_fuzz_query():
    plan = route_agents("run afl fuzz")
    assert "afl" in plan
    assert "critic" in plan
