from pydantic import BaseModel

class InputGuardrailResponse(BaseModel):
    is_valid_query: bool
    rationale: str
