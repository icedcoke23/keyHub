"""LLM 供应商配置：上游地址、header 格式、价格表（用于成本估算）。

价格单位：USD / 1M tokens。若未配置，成本记为 0。
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ProviderConfig:
    name: str
    base_url: str
    # 如何把 api key 放入请求头
    header_name: str = "Authorization"
    header_prefix: str = "Bearer "
    # 是否把 key 放入 body（如 deepseek 兼容 OpenAI，但仍用 header）
    body_key_field: str | None = None
    # chat completions 路径
    chat_path: str = "/v1/chat/completions"
    # 是否兼容 OpenAI 响应格式（用于解析 usage）
    openai_compatible: bool = True


# 内置供应商配置
PROVIDERS: dict[str, ProviderConfig] = {
    "openai": ProviderConfig(
        name="openai",
        base_url="https://api.openai.com",
    ),
    "anthropic": ProviderConfig(
        name="anthropic",
        base_url="https://api.anthropic.com",
        header_name="x-api-key",
        header_prefix="",
        chat_path="/v1/messages",
        openai_compatible=False,
    ),
    "deepseek": ProviderConfig(
        name="deepseek",
        base_url="https://api.deepseek.com",
    ),
    "qwen": ProviderConfig(
        name="qwen",
        base_url="https://dashscope.aliyuncs.com/compatible-mode",
    ),
    "glm": ProviderConfig(
        name="glm",
        base_url="https://open.bigmodel.cn/api/paas",
    ),
    "moonshot": ProviderConfig(
        name="moonshot",
        base_url="https://api.moonshot.cn",
    ),
    # 自定义兼容端点（用户可在运行时覆盖 base_url）
    "custom": ProviderConfig(
        name="custom",
        base_url="",
    ),
}


# 价格表 USD / 1M tokens（粗略估算，仅用于成本汇总，非计费依据）
# 结构: { provider: { model_prefix: (input_per_1m, output_per_1m) } }
PRICING: dict[str, dict[str, tuple[float, float]]] = {
    "openai": {
        "gpt-4o": (2.5, 10.0),
        "gpt-4o-mini": (0.15, 0.6),
        "gpt-4-turbo": (10.0, 30.0),
        "gpt-3.5": (0.5, 1.5),
        "o1": (15.0, 60.0),
        "o3-mini": (1.1, 4.4),
    },
    "anthropic": {
        "claude-3-5-sonnet": (3.0, 15.0),
        "claude-3-5-haiku": (0.8, 4.0),
        "claude-3-opus": (15.0, 75.0),
        "claude-3-sonnet": (3.0, 15.0),
        "claude-3-haiku": (0.25, 1.25),
    },
    "deepseek": {
        "deepseek-chat": (0.14, 0.28),
        "deepseek-reasoner": (0.55, 2.19),
    },
    "qwen": {
        "qwen-max": (2.88, 8.64),
        "qwen-plus": (0.4, 1.2),
        "qwen-turbo": (0.05, 0.2),
    },
    "glm": {
        "glm-4": (0.5, 0.5),
        "glm-4-plus": (7.14, 7.14),
        "glm-4-flash": (0.0, 0.0),
    },
    "moonshot": {
        "moonshot-v1-8k": (1.68, 1.68),
        "moonshot-v1-32k": (3.36, 3.36),
        "moonshot-v1-128k": (8.4, 8.4),
    },
}


def estimate_cost(provider: str, model: str, prompt_tokens: int, completion_tokens: int) -> float:
    table = PRICING.get(provider, {})
    # 按前缀匹配
    price = None
    for prefix, p in table.items():
        if model.startswith(prefix):
            price = p
            break
    if price is None:
        return 0.0
    in_cost = prompt_tokens / 1_000_000 * price[0]
    out_cost = completion_tokens / 1_000_000 * price[1]
    return round(in_cost + out_cost, 6)


def get_provider(name: str) -> ProviderConfig:
    if name not in PROVIDERS:
        # 未知供应商默认按 OpenAI 兼容处理
        return ProviderConfig(name=name, base_url="")
    return PROVIDERS[name]
