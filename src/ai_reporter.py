import os
import json
from typing import Any, Dict, Optional, Union
from langchain_google_genai import ChatGoogleGenerativeAI



def generate_ai_report(analysis_data: Dict[str, Any], gemini_api_key: Optional[str] = None) -> Union[Dict[str, Any], str]:
    """Generate a narrative report AND a structured classification in a single LLM call.

    Args:
        analysis_data: Collected evidence dict (URLs, hashes, ML prediction, VT/Sucuri/PhishTank, etc.).
        gemini_api_key: Optional override for GEMINI_API_KEY env var.

    Returns:
        Dict with keys {"analysis_text", "classification"} on success; otherwise a plain error string.
    """
    api_key = gemini_api_key or os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return "Error: GEMINI_API_KEY not found. Please set it as an environment variable."

    llm = ChatGoogleGenerativeAI(
        model="gemini-2.0-flash",
        google_api_key=api_key,
        temperature=0.2,
        max_output_tokens=1024,
    )

    schema_example = {
        "analysis_text": "string - succinct narrative suitable for end users",
        "classification": {
            "overall_status": "safe|warning|danger",
            "status_line": "one-sentence summary",
            "recommendation": "actionable next step",
            "cards": [
                {
                    "category": "Machine Learning Prediction",
                    "severity": "safe|warning|danger",
                    "subtitle": "optional short subtitle",
                    "description": "short explanation"
                }
            ]
        }
    }

    prompt = (
        "You are a careful cybersecurity assistant.\n"
        "Given the following technical JSON input, produce a concise end-user narrative AND a strict JSON classification.\n"
        "Rules:\n"
        "- Reflect evidence faithfully.\n"
        "- Single VirusTotal engine flag or a Sucuri 'C' rating => warning, not danger.\n"
        "- 'Blocked from accessing' due to API/WAF/rate limits => warning.\n"
        "- Blacklisted, browser/security blocked, multiple engines detecting, or cert issues => danger.\n"
        "- Strong ML-benign with no hard-danger => safe.\n"
        "Output ONLY JSON (no markdown) matching this schema: \n"
        f"{json.dumps(schema_example, ensure_ascii=False)}\n\n"
        f"Technical input: {json.dumps(analysis_data, ensure_ascii=False)}"
    )

    try:
        response = llm.invoke(prompt)
        raw = response.content if hasattr(response, "content") else str(response)
        try:
            obj = json.loads(raw)
        except Exception:
            start = raw.find("{")
            end = raw.rfind("}")
            if start != -1 and end != -1 and end > start:
                obj = json.loads(raw[start:end+1])
            else:
                return raw

        analysis_text = obj.get("analysis_text") or ""
        classification = obj.get("classification") or {}
        status = (classification.get("overall_status") or "").strip().lower()
        if status not in {"safe", "warning", "danger"}:
            classification = None

        if classification and "cards" in classification and not isinstance(classification["cards"], list):
            classification["cards"] = []

        return {"analysis_text": analysis_text, "classification": classification}
    except Exception as e:
        return f"Error generating AI report: {e}"
