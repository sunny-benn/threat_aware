import os
from langchain_google_genai import ChatGoogleGenerativeAI



def generate_ai_report(analysis_data, gemini_api_key=None):
    """Generates a human-readable security report using an LLM.

    Args:
        analysis_data (dict): A dictionary containing all the collected evidence.
        openai_api_key (str, optional): The OpenAI API key. Defaults to env variable.

    Returns:
        str: The AI-generated report.
    """
    api_key = gemini_api_key or os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return "Error: GEMINI_API_KEY not found. Please set it as an environment variable."

    llm = ChatGoogleGenerativeAI(
        model="gemini-2.0-flash",  # cost-effective fast model
        google_api_key=api_key,
        temperature=0.5,
        max_output_tokens=512,
    )

    # Construct a detailed prompt with all the evidence
    prompt = f"""You are a friendly cybersecurity expert explaining a potentially malicious email to a non-technical user. 
    Based on the following technical data, write a simple, clear, and concise report. 
    Start with a one-sentence summary (e.g., 'This email looks safe,' or 'This email is suspicious and likely a phishing attempt.').
    Then, explain the key findings in bullet points. For each finding, explain what it means in simple terms.
    Finally, provide a clear recommendation on what the user should do next (e.g., 'delete this email immediately' or 'it's safe to reply').

    Here is the technical data:
    {analysis_data}
    """

    try:
        response = llm.invoke(prompt)
        return response.content if hasattr(response, "content") else str(response)
    except Exception as e:
        return f"Error generating AI report: {e}"
