from dataclasses import dataclass

@dataclass
class Config:
    timeout: int = 5
    user_agent: str = "Sentinel/1.0"
    verify_tls: bool = True