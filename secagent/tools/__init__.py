from secagent.tools.builtin_sast import BuiltinSastAgent
from secagent.tools.fuzz_afl import AflAgent
from secagent.tools.llm_review import LlmReviewAgent
from secagent.tools.sast_codeql import CodeqlAgent
from secagent.tools.sast_semgrep import SemgrepAgent

AGENTS = {
    "semgrep": SemgrepAgent(),
    "codeql": CodeqlAgent(),
    "builtin_sast": BuiltinSastAgent(),
    "afl": AflAgent(),
    "llm_review": LlmReviewAgent(),
}


def register(agent) -> None:
    AGENTS[agent.name] = agent
